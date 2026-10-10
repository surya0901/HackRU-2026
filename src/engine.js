import { parse } from '@babel/parser';

/** Deterministic static evidence. No source is executed by this module. */
export const ENGINE_VERSION = '1.0.0';

const SOURCE_EXTENSIONS = /\.(?:[cm]?js|jsx|ts|tsx)$/i;
const SECRET_PATTERNS = [
  ['private-key', /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/g],
  ['github-token', /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,})\b/g],
  ['openai-key', /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b/g],
  ['aws-access-key', /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g],
  ['slack-token', /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g],
  ['google-api-key', /\bAIza[A-Za-z0-9_-]{30,}\b/g],
  ['stripe-secret', /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g],
  ['sendgrid-key', /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g],
  ['url-credential', /\bhttps?:\/\/[^\s/"'`:@]+:[^\s/"'`@]+@[^\s/"'`]+/g],
];
const CREDENTIAL_NAME = /(?:api[_-]?key|access[_-]?key|secret|password|passwd|token|credential|private[_-]?key|authorization)/i;
const PLACEHOLDER = /^(?:\$\{|\$[A-Z_]+$|<|\[|(?:your|example|sample|placeholder|dummy|test)[_-]|changeme|replace|redacted|process\.env)/i;

function entropy(value) {
  const counts = new Map();
  for (const ch of value) counts.set(ch, (counts.get(ch) || 0) + 1);
  let result = 0;
  for (const count of counts.values()) { const p = count / value.length; result -= p * Math.log2(p); }
  return result;
}

function secretCandidates(content) {
  const found = [];
  for (const [kind, pattern] of SECRET_PATTERNS) {
    for (const match of content.matchAll(new RegExp(pattern.source, pattern.flags))) {
      found.push({ kind, value: match[0], index: match.index, name: kind, confidence: 'high' });
    }
  }
  // A literal is a candidate only when its name suggests a credential. Entropy
  // alone cannot establish that arbitrary source text is a credential.
  const assignment = /["']?([A-Za-z_$][\w$.-]*(?:\[["'][^"']+["']\])?)["']?\s*[:=]\s*(["'`])([^"'`\r\n]{8,})\2/g;
  for (const match of content.matchAll(assignment)) {
    const value = match[3];
    if (!CREDENTIAL_NAME.test(match[1]) || PLACEHOLDER.test(value)) continue;
    if (value.length < 16 || entropy(value) < 3.2) continue;
    const valueIndex = match.index + match[0].indexOf(value);
    found.push({ kind: 'credential-literal', value, index: valueIndex, name: match[1], confidence: 'medium' });
  }
  const unique = new Map();
  for (const candidate of found) {
    const key = `${candidate.index}:${candidate.value}`;
    if (!unique.has(key)) unique.set(key, candidate);
  }
  return [...unique.values()].sort((a, b) => a.index - b.index || a.kind.localeCompare(b.kind));
}

/** Redacts entire candidate values, including other credentials on the line. */
export function redactSecrets(text, additionalValues = []) {
  let clean = String(text ?? '');
  const values = [...secretCandidates(clean).map(item => item.value), ...additionalValues]
    .filter(value => typeof value === 'string' && value.length)
    .sort((a, b) => b.length - a.length);
  for (const value of new Set(values)) clean = clean.split(value).join('[REDACTED]');
  return clean;
}

/** Stable synchronous digest; inputs must contain semantic identity, not lines. */
export function stableFingerprint(parts) {
  const bytes = new TextEncoder().encode(JSON.stringify(Array.isArray(parts) ? parts : [parts]));
  // Four independent FNV-1a streams provide a stable 128-bit identifier in both
  // browsers and Node. This is an identity digest, not an authentication token.
  const seeds = [0x811c9dc5, 0x9e3779b9, 0x85ebca6b, 0xc2b2ae35];
  return seeds.map(seed => {
    let hash = seed;
    for (const byte of bytes) { hash ^= byte; hash = Math.imul(hash, 0x01000193) >>> 0; }
    return hash.toString(16).padStart(8, '0');
  }).join('');
}

function repositoryName(value) {
  if (typeof value === 'string') return value.replace(/^https:\/\/github\.com\//i, '').replace(/\.git\/?$/, '').replace(/\/$/, '');
  if (value && typeof value === 'object') return value.fullName || value.full_name || `${value.owner || ''}/${value.repo || value.name || ''}`;
  return '';
}

function normalizeFile(file) { return String(file || '').replace(/\\/g, '/').replace(/^\.\//, ''); }
function unwrap(node) {
  while (node && ['TSAsExpression', 'TSSatisfiesExpression', 'TSNonNullExpression', 'TypeCastExpression', 'ParenthesizedExpression'].includes(node.type)) node = node.expression;
  return node;
}
function keyName(node) {
  if (!node) return null;
  if (node.type === 'Identifier') return node.name;
  if (['StringLiteral', 'NumericLiteral'].includes(node.type)) return String(node.value);
  return null;
}
function literal(node) {
  node = unwrap(node);
  if (node?.type === 'StringLiteral' || node?.type === 'NumericLiteral' || node?.type === 'BooleanLiteral') return node.value;
  if (node?.type === 'TemplateLiteral' && node.expressions.length === 0) return node.quasis.map(part => part.value.cooked).join('');
  return null;
}
function properties(node) {
  node = unwrap(node);
  if (node?.type !== 'ObjectExpression') return new Map();
  const result = new Map();
  for (const prop of node.properties) {
    const key = prop.computed ? literal(prop.key) : keyName(prop.key);
    // A later spread or unknown computed key can overwrite an earlier tools,
    // name, method, or execute property. Only fields declared after it are known.
    if (prop.type === 'SpreadElement' || key === null) { result.clear(); continue; }
    if (['ObjectProperty', 'ObjectMethod'].includes(prop.type)) result.set(String(key), prop.type === 'ObjectMethod' ? prop : unwrap(prop.value));
  }
  return result;
}
function memberParts(node) {
  node = unwrap(node);
  if (node?.type === 'Identifier') return [node.name];
  if (node?.type === 'MemberExpression' || node?.type === 'OptionalMemberExpression') {
    const base = memberParts(node.object);
    const key = node.computed ? literal(node.property) : keyName(node.property);
    return base && key !== null ? [...base, String(key)] : null;
  }
  return null;
}
function walk(node, visit, parent = null) {
  if (!node || typeof node !== 'object') return;
  if (Array.isArray(node)) { for (const child of node) walk(child, visit, parent); return; }
  if (!node.type) return;
  if (visit(node, parent) === false) return;
  for (const [key, child] of Object.entries(node)) {
    if (['loc', 'start', 'end', 'extra', 'comments', 'leadingComments', 'trailingComments', 'innerComments', 'tokens', 'errors'].includes(key)) continue;
    if (child && typeof child === 'object') walk(child, visit, node);
  }
}

const AGENT_IMPORTS = new Set(['@openai/agents', '@openai/agents-core', 'langchain', 'langchain/agents', '@langchain/langgraph/prebuilt']);
const TOOL_IMPORTS = new Set(['@openai/agents', '@openai/agents-core', '@langchain/core/tools', 'langchain/tools']);
function moduleKind(imported) {
  const module = imported?.source || '';
  if (/^(?:node:)?child_process$/.test(module)) return 'process';
  if (/^(?:node:)?fs(?:\/promises)?$/.test(module)) return 'filesystem';
  if (module === 'stripe') return 'stripe';
  if (module === '@prisma/client') return 'database';
  if (module === 'mongodb') return 'database';
  if (module === 'pg' || module === 'knex' || module === '@supabase/supabase-js') return 'database';
  if (module === 'axios') return 'http';
  return null;
}

function importRole(index, callee, names, allowedModules) {
  const parts = memberParts(callee);
  if (!parts || parts.length > 2) return false;
  const imported = index.imports.get(parts[0]);
  if (!imported || !allowedModules.has(imported.source)) return false;
  const exportedName = parts.length === 1 ? imported.imported : parts[1];
  return names.includes(exportedName);
}

function indexSource(source, ast) {
  const index = { ...source, ast, imports: new Map(), definitions: new Map(), exports: new Map(), parents: new WeakMap(), functionBindings: new WeakMap(), agents: [] };
  walk(ast, (node, parent) => { if (parent) index.parents.set(node, parent); });
  for (const statement of ast.program.body) {
    if (statement.type === 'ImportDeclaration') {
      if (statement.importKind === 'type') continue;
      for (const specifier of statement.specifiers) {
        if (specifier.importKind === 'type') continue;
        index.imports.set(specifier.local.name, {
          source: statement.source.value,
          imported: specifier.type === 'ImportDefaultSpecifier' ? 'default' : specifier.type === 'ImportNamespaceSpecifier' ? '*' : keyName(specifier.imported),
          node: specifier,
        });
      }
    }
    if (statement.type === 'ExportNamedDeclaration') {
      for (const specifier of statement.specifiers || []) {
        if (!statement.source) index.exports.set(keyName(specifier.exported), keyName(specifier.local));
        else index.exports.set(keyName(specifier.exported), { source: statement.source.value, imported: keyName(specifier.local) });
      }
    }
    if (statement.type === 'ExportDefaultDeclaration') {
      const declared = statement.declaration;
      if (declared.type === 'Identifier') index.exports.set('default', declared.name);
      else if (declared.id?.name) {
        index.exports.set('default', declared.id.name);
        if (declared.type === 'FunctionDeclaration') index.definitions.set(declared.id.name, { name: declared.id.name, node: declared, value: declared, index });
      }
      else if (['FunctionExpression', 'ArrowFunctionExpression', 'FunctionDeclaration'].includes(declared.type)) {
        index.definitions.set('$default', { name: '$default', node: declared, value: declared, index });
        index.exports.set('default', '$default');
      }
    }
    const declared = statement.type === 'ExportNamedDeclaration' ? statement.declaration : statement;
    if (!declared) continue;
    if (declared.type === 'FunctionDeclaration' && declared.id) {
      index.definitions.set(declared.id.name, { name: declared.id.name, node: declared, value: declared, index });
      if (statement.type === 'ExportNamedDeclaration') index.exports.set(declared.id.name, declared.id.name);
    }
    if (declared.type === 'VariableDeclaration') {
      for (const variable of declared.declarations) {
        if (variable.id.type === 'Identifier') {
          index.definitions.set(variable.id.name, { name: variable.id.name, node: variable, value: unwrap(variable.init), index });
          if (statement.type === 'ExportNamedDeclaration') index.exports.set(variable.id.name, variable.id.name);
        } else if (variable.id.type === 'ObjectPattern' && variable.init?.type === 'CallExpression' && variable.init.callee?.name === 'require' && literal(variable.init.arguments[0])) {
          for (const prop of variable.id.properties) {
            if (prop.type === 'ObjectProperty' && prop.value.type === 'Identifier') index.imports.set(prop.value.name, { source: literal(variable.init.arguments[0]), imported: keyName(prop.key), node: prop });
          }
        }
        if (variable.id.type === 'Identifier' && variable.init?.type === 'CallExpression' && variable.init.callee?.name === 'require' && literal(variable.init.arguments[0])) {
          index.imports.set(variable.id.name, { source: literal(variable.init.arguments[0]), imported: '*', node: variable });
        }
      }
    }
  }
  return index;
}

function bindingNames(pattern, names) {
  if (!pattern) return;
  if (pattern.type === 'Identifier') names.add(pattern.name);
  else if (pattern.type === 'RestElement') bindingNames(pattern.argument, names);
  else if (pattern.type === 'AssignmentPattern') bindingNames(pattern.left, names);
  else if (pattern.type === 'ArrayPattern') for (const item of pattern.elements) bindingNames(item, names);
  else if (pattern.type === 'ObjectPattern') for (const item of pattern.properties) bindingNames(item.type === 'RestElement' ? item.argument : item.value, names);
}

// Nested bindings can hide a module import or agent variable. Conservatively
// exclude a scope when it redeclares the root symbol rather than infer an edge.
function isShadowedAt(index, node, name) {
  let parent = index.parents.get(node);
  while (parent && parent.type !== 'Program') {
    if (['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression', 'ObjectMethod', 'ClassMethod'].includes(parent.type)) {
      let names = index.functionBindings.get(parent);
      if (!names) {
        names = new Set();
        for (const parameter of parent.params || []) bindingNames(parameter, names);
        walk(parent.body, child => {
          if (['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression', 'ObjectMethod', 'ClassMethod'].includes(child.type)) {
            if (child.type === 'FunctionDeclaration' && child.id) names.add(child.id.name);
            return false;
          }
          if (child.type === 'VariableDeclarator') bindingNames(child.id, names);
          if (child.type === 'CatchClause') bindingNames(child.param, names);
        });
        index.functionBindings.set(parent, names);
      }
      if (names.has(name)) return true;
    }
    parent = index.parents.get(parent);
  }
  return false;
}

function enclosingSymbol(index, node) {
  let parent = index.parents.get(node);
  while (parent && parent.type !== 'Program') {
    if (parent.type === 'FunctionDeclaration' && parent.id) return parent.id.name;
    if (parent.type === 'VariableDeclarator' && parent.id.type === 'Identifier') return parent.id.name;
    parent = index.parents.get(parent);
  }
  return '$module';
}

function resolveModule(from, specifier, indices) {
  if (!specifier.startsWith('.')) return null;
  const segments = from.split('/').slice(0, -1);
  for (const segment of specifier.split('/')) {
    if (!segment || segment === '.') continue;
    if (segment === '..') segments.pop(); else segments.push(segment);
  }
  const base = segments.join('/');
  const candidates = [base, ...['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'].map(ext => base + ext), ...['.ts', '.tsx', '.js', '.jsx'].map(ext => `${base}/index${ext}`)];
  // TypeScript ESM commonly uses a .js import for an actual .ts source file.
  if (/\.js$/.test(base)) candidates.push(base.replace(/\.js$/, '.ts'), base.replace(/\.js$/, '.tsx'));
  return candidates.map(path => indices.get(path)).find(Boolean) || null;
}

function resolveDefinition(index, name, indices, seen = new Set()) {
  const identity = `${index.path}:${name}`;
  if (seen.has(identity)) return null;
  seen.add(identity);
  const definition = index.definitions.get(name);
  if (definition) {
    if (definition.value?.type === 'Identifier') return resolveDefinition(index, definition.value.name, indices, seen);
    return definition;
  }
  const imported = index.imports.get(name);
  if (!imported) return null;
  const target = resolveModule(index.path, imported.source, indices);
  if (!target) return null;
  const exported = target.exports.get(imported.imported);
  if (typeof exported === 'string') return resolveDefinition(target, exported, indices, seen);
  if (exported?.source) {
    const next = resolveModule(target.path, exported.source, indices);
    const final = next?.exports.get(exported.imported);
    return next && typeof final === 'string' ? resolveDefinition(next, final, indices, seen) : null;
  }
  return null;
}

function resolveExpression(index, node, indices, seen = new Set()) {
  node = unwrap(node);
  if (node?.type !== 'Identifier') return { node, index };
  const definition = resolveDefinition(index, node.name, indices, seen);
  return definition ? { node: definition.value, index: definition.index, definition } : { node, index };
}

function callable(definition, indices) {
  if (!definition) return null;
  let { value, index } = definition;
  value = unwrap(value);
  if (['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression', 'ObjectMethod'].includes(value?.type)) return { ...definition, body: value, label: definition.name };
  const toolFactory = value && (value.type === 'CallExpression' || value.type === 'NewExpression') && importRole(index, value.callee, ['tool', 'DynamicTool', 'DynamicStructuredTool'], TOOL_IMPORTS);
  if (!toolFactory) return null;
  const config = properties(value.arguments[0]);
  const secondConfig = properties(value.arguments[1]);
  const bodyNode = config.get('execute') || config.get('func') || value.arguments[0];
  const resolved = resolveExpression(index, bodyNode, indices);
  if (!['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression', 'ObjectMethod'].includes(resolved.node?.type)) return null;
  return { ...definition, body: resolved.node, bodyIndex: resolved.index, label: literal(config.get('name') || secondConfig.get('name')) || definition.name };
}

function resolveService(index, identifier, indices, seen = new Set()) {
  const parts = memberParts(identifier);
  if (!parts) return null;
  const importInfo = index.imports.get(parts[0]);
  const kind = moduleKind(importInfo);
  if (kind && ['process', 'filesystem', 'http'].includes(kind)) return { kind, root: parts[0], imported: importInfo, binding: null, index };
  const definition = resolveDefinition(index, parts[0], indices, seen);
  const value = definition?.value;
  if (value?.type !== 'NewExpression' && value?.type !== 'CallExpression') return null;
  const constructor = memberParts(value.callee);
  if (!constructor || constructor.length > 2) return null;
  const source = constructor && definition.index.imports.get(constructor[0]);
  const constructedKind = moduleKind(source);
  const importedName = constructor?.length > 1 ? constructor[1] : source?.imported;
  const supportedConstructors = {
    stripe: ['default', '*', 'Stripe'],
    '@prisma/client': ['PrismaClient'],
    mongodb: ['MongoClient', 'Db', 'Collection'],
    pg: ['Client', 'Pool'],
    knex: ['default', '*', 'knex'],
    '@supabase/supabase-js': ['createClient'],
    axios: ['create'],
  };
  if (constructedKind && supportedConstructors[source.source]?.includes(importedName)) return { kind: constructedKind, root: parts[0], imported: source, binding: definition, index: definition.index };
  return null;
}

function credentialReference(node) {
  const parts = memberParts(node);
  return parts?.length === 3 && parts[0] === 'process' && parts[1] === 'env' && CREDENTIAL_NAME.test(parts[2]) ? parts[2] : null;
}

function credentialType(name) {
  if (/stripe/i.test(name)) return 'Stripe credential reference';
  if (/openai/i.test(name)) return 'OpenAI credential reference';
  if (/github|gh_token/i.test(name)) return 'GitHub credential reference';
  if (/aws/i.test(name)) return 'AWS credential reference';
  if (/database|db_|mongo|postgres/i.test(name)) return 'Database credential reference';
  return 'Credential reference';
}

function sensitiveOperation(index, node, indices, localNames = new Set()) {
  if (node.type !== 'CallExpression' && node.type !== 'NewExpression') return null;
  const parts = memberParts(node.callee);
  if (!parts) return null;
  if (localNames.has(parts[0]) || isShadowedAt(index, node, parts[0])) return null;
  const method = parts.at(-1);
  const service = resolveService(index, node.callee, indices);
  const importInfo = index.imports.get(parts[0]);
  if (service && !service.binding && parts.length > 1) {
    const allowedReceivers = service.kind === 'filesystem' ? ['*', 'default', 'promises'] : service.kind === 'http' ? ['*', 'default', 'axios'] : ['*', 'default'];
    if (!allowedReceivers.includes(importInfo?.imported)) return null;
  }
  if (service?.kind === 'process') {
    const invoked = parts.length === 1 ? importInfo?.imported : method;
    if (parts.length <= 2 && ['exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync', 'fork'].includes(invoked)) return { category: 'process-execution', label: 'Operating-system process execution', action: `${parts.join('.')} call`, relation: 'CAN_TRIGGER', service };
  }
  if (service?.kind === 'filesystem') {
    if (parts.length > 2 && !(parts.length === 3 && parts[1] === 'promises')) return null;
    const invoked = parts.length === 1 ? importInfo?.imported : method;
    if (['rm', 'rmSync', 'rmdir', 'rmdirSync', 'unlink', 'unlinkSync'].includes(invoked)) return { category: 'file-deletion', label: 'Filesystem deletion', action: `${parts.join('.')} call`, relation: 'WRITES', service };
    if (['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync'].includes(invoked)) return { category: 'file-write', label: 'Filesystem write', action: `${parts.join('.')} call`, relation: 'WRITES', service };
  }
  const financialMethods = { refunds: ['create', 'update', 'cancel'], charges: ['create', 'update', 'capture'], paymentIntents: ['create', 'update', 'cancel', 'confirm'], transfers: ['create', 'update'], payouts: ['create', 'update', 'cancel'] };
  if (service?.kind === 'stripe' && parts.length === 3 && financialMethods[parts[1]]?.includes(method)) {
    return { category: 'financial-action', label: `Stripe ${parts[1]}.${method}`, action: `Stripe ${parts[1]}.${method}`, relation: 'CAN_TRIGGER', service };
  }
  if (service?.kind === 'database') {
    const databaseModule = service.imported.source;
    const constructor = memberParts(service.binding.value.callee);
    const constructorName = constructor.length === 1 ? service.imported.imported : constructor.at(-1);
    const mutationMethods = databaseModule === '@prisma/client' && parts.length === 3 ? ['delete', 'deleteMany', 'update', 'updateMany', 'create', 'createMany', 'upsert']
      : databaseModule === 'mongodb' && parts.length === 2 && constructorName === 'Collection' ? ['deleteOne', 'deleteMany', 'updateOne', 'updateMany', 'insertOne', 'insertMany', 'replaceOne', 'drop']
        : databaseModule === 'mongodb' && parts.length === 2 && constructorName === 'Db' ? ['dropDatabase', 'dropCollection'] : [];
    if (mutationMethods.includes(method)) {
      return { category: /delete|drop/.test(method) ? 'record-deletion' : 'record-write', label: `Database ${parts.slice(1).join('.')}`, action: `Database method ${parts.slice(1).join('.')}`, relation: 'WRITES', service };
    }
    const sqlMethod = parts.length === 2 && ((databaseModule === 'pg' && method === 'query') || (databaseModule === '@prisma/client' && ['$executeRawUnsafe', '$executeRaw'].includes(method)));
    if (sqlMethod) {
      const sql = literal(node.arguments[0]);
      if (typeof sql === 'string' && /^\s*(?:DELETE|UPDATE|INSERT|DROP|TRUNCATE|ALTER)\b/i.test(sql)) return { category: /^(?:\s*)(?:DELETE|DROP|TRUNCATE)\b/i.test(sql) ? 'record-deletion' : 'record-write', label: 'Database mutation query', action: `Database ${method} with mutation SQL`, relation: 'WRITES', service };
    }
  }
  if (service?.kind === 'http' && parts.length === 2 && ['delete', 'put', 'patch'].includes(method)) return { category: method === 'delete' ? 'http-delete' : 'http-write', label: `HTTP ${method.toUpperCase()} request`, action: `${parts.join('.')} request`, relation: 'WRITES', service };
  if (parts.length === 1 && parts[0] === 'fetch' && !index.definitions.has('fetch') && !index.imports.has('fetch') && !localNames.has('fetch')) {
    const config = properties(node.arguments[1]);
    const verb = literal(config.get('method'));
    if (typeof verb === 'string' && ['DELETE', 'PUT', 'PATCH'].includes(verb.toUpperCase())) return { category: verb.toUpperCase() === 'DELETE' ? 'http-delete' : 'http-write', label: `HTTP ${verb.toUpperCase()} request`, action: `fetch with method ${verb.toUpperCase()}`, relation: 'WRITES', service: null };
  }
  if (parts.length === 1 && ['eval', 'Function'].includes(parts[0]) && !index.definitions.has(parts[0]) && !index.imports.has(parts[0]) && !localNames.has(parts[0])) return { category: 'dynamic-code', label: 'Dynamic JavaScript execution', action: `${parts[0]} expression`, relation: 'CAN_TRIGGER', service: null };
  return null;
}

function impact(category) {
  const descriptions = {
    'financial-action': ['The configured tool contains a call capable of performing a financial action.', 'Financial operations need an appropriate authorization boundary because changing money-related state can affect customers and the company.'],
    'record-deletion': ['The configured tool contains a database deletion operation.', 'If this capability is used without appropriate authorization, customer or company records could be deleted.'],
    'record-write': ['The configured tool contains an operation that can change database records.', 'If this capability is used without appropriate authorization, customer or company records could be changed.'],
    'process-execution': ['The configured tool contains a call that starts an operating-system process.', 'A process may access the application environment and its permissions; unsafe inputs would require a separate data-flow review.'],
    'file-deletion': ['The configured tool contains a filesystem deletion call.', 'A deletion operation can remove files available to the application process.'],
    'file-write': ['The configured tool contains a filesystem write call.', 'A write operation can change files available to the application process.'],
    'http-delete': ['The configured tool sends an HTTP DELETE request.', 'The remote service determines the effect and authorization of the request; a deletion endpoint may remove remote data.'],
    'http-write': ['The configured tool sends an HTTP request using a mutation method.', 'The remote service determines the effect and authorization of the request; it may change remote data.'],
    'dynamic-code': ['The configured tool contains a dynamic JavaScript execution expression.', 'Executing code assembled at runtime requires a separate review of where its inputs originate.'],
  };
  return descriptions[category] || ['A sensitive operation appears in the configured tool.', 'Review the operation and the permissions available to the application.'];
}

function capabilityTitle(agent, category) {
  const action = {
    'financial-action': 'perform a financial action',
    'record-deletion': 'delete database records',
    'record-write': 'change database records',
    'process-execution': 'start system processes',
    'file-deletion': 'delete application files',
    'file-write': 'change application files',
    'http-delete': 'send a deletion request to another service',
    'http-write': 'send a request that can change another service',
    'dynamic-code': 'execute dynamically created JavaScript',
  }[category] || 'perform a sensitive operation';
  return `${agent} has a tool that can ${action}`;
}

/** Traverses only evidenced observed edges. A path is static, never an exploit. */
export function derivePaths(graph, context = {}) {
  const nodes = new Map((graph?.nodes || []).filter(node => node?.id).map(node => [node.id, node]));
  const outgoing = new Map();
  for (const edge of graph?.edges || []) {
    if (edge?.status !== 'OBSERVED' || !nodes.has(edge.from) || !nodes.has(edge.to) || !Array.isArray(edge.evidence) || !edge.evidence.length) continue;
    if (edge.evidence.some(evidence => !evidence.file || !Number.isInteger(evidence.line) || evidence.line < 1 || !evidence.rule || typeof evidence.snippet !== 'string' || !evidence.repository || !evidence.commit)) continue;
    if (context.repository && edge.evidence.some(evidence => repositoryName(evidence.repository) !== repositoryName(context.repository))) continue;
    if (context.commit && edge.evidence.some(evidence => evidence.commit !== context.commit)) continue;
    if (!outgoing.has(edge.from)) outgoing.set(edge.from, []);
    outgoing.get(edge.from).push(edge);
  }
  for (const edges of outgoing.values()) edges.sort((a, b) => String(a.id).localeCompare(String(b.id)));
  const paths = new Map();
  const starts = [...nodes.values()].filter(node => node.type === 'InputSource' || node.type === 'Agent').sort((a, b) => a.id.localeCompare(b.id));
  for (const start of starts) {
    const stack = [{ nodeIds: [start.id], edges: [] }];
    while (stack.length && paths.size < 250) {
      const current = stack.pop();
      const tail = nodes.get(current.nodeIds.at(-1));
      if (tail.type === 'SensitiveResource' && current.edges.length && current.nodeIds.some(id => nodes.get(id).type === 'Agent') && current.nodeIds.some(id => nodes.get(id).type === 'Tool')) {
        const relationships = current.edges.map(edge => [edge.from, edge.relation, edge.to]);
        const fingerprint = stableFingerprint([repositoryName(context.repository || context.repo), 'static-capability-path', relationships]);
        const chainNodes = current.nodeIds.map(id => nodes.get(id));
        const evidence = current.edges.flatMap(edge => edge.evidence);
        const unique = new Map(evidence.map(item => [`${item.file}:${item.line}:${item.rule}`, item]));
        const hasInput = chainNodes.some(node => node.type === 'InputSource');
        paths.set(fingerprint, {
          id: `path-${fingerprint}`, fingerprint, status: 'DERIVED', evidenceType: 'DERIVED',
          staticStatus: 'REACHABLE', staticReachability: 'REACHABLE', exploitStatus: 'UNVERIFIED', exploit: 'UNVERIFIED', nodeIds: current.nodeIds, edgeIds: current.edges.map(edge => edge.id),
          nodes: chainNodes, edges: current.edges, chain: chainNodes.map(node => node.label), provenance: [...unique.values()],
          title: hasInput ? 'External input reaches an agent with a sensitive capability' : 'Agent is configured with a sensitive capability',
          detail: 'This path follows explicit source or configuration relationships. Successful manipulation and unauthorized execution have not been tested.',
          prerequisites: { externalInput: hasInput, agent: true, tool: true, sensitiveOperation: true, successfulManipulation: false },
          proven: 'The static source relationships connect the agent to the registered tool and its sensitive operation.',
          notProven: 'No exploit, unauthorized action, runtime execution, or effectiveness of an approval control was tested.',
        });
        continue;
      }
      if (current.edges.length >= 8) continue;
      for (const edge of outgoing.get(tail.id) || []) {
        if (!current.nodeIds.includes(edge.to)) stack.push({ nodeIds: [...current.nodeIds, edge.to], edges: [...current.edges, edge] });
      }
    }
  }
  return [...paths.values()].sort((a, b) => Number(b.prerequisites.externalInput) - Number(a.prerequisites.externalInput) || a.id.localeCompare(b.id));
}

function removalPatch(index, array, element, clean, evidence, commit) {
  if (!array || array.type !== 'ArrayExpression' || array.elements.some(item => !item || item.type === 'SpreadElement')) return null;
  const position = array.elements.indexOf(element);
  if (position < 0) return null;
  let start = element.start; let end = element.end;
  if (array.elements.length === 1) {
    const tail = index.content.slice(end, array.end - 1);
    if (/\/\*|\/\//.test(tail)) return null;
    const comma = tail.indexOf(',');
    if (comma >= 0) end += comma + 1;
  }
  if (array.elements.length > 1) {
    if (position < array.elements.length - 1) {
      const between = index.content.slice(end, array.elements[position + 1].start);
      const comma = between.indexOf(',');
      if (comma < 0 || /\/\*|\/\//.test(between)) return null;
      end += comma + 1;
    } else {
      const previous = array.elements[position - 1];
      const between = index.content.slice(previous.end, start);
      const comma = between.indexOf(',');
      if (comma < 0 || /\/\*|\/\//.test(between)) return null;
      start = previous.end + comma;
    }
  }
  const changed = index.content.slice(0, start) + index.content.slice(end);
  const before = index.content.split('\n'); const after = changed.split('\n');
  const oldEndsWithNewline = index.content.endsWith('\n'); const newEndsWithNewline = changed.endsWith('\n');
  if (oldEndsWithNewline) before.pop();
  if (newEndsWithNewline) after.pop();
  let first = 0;
  while (first < before.length && first < after.length && before[first] === after[first]) first++;
  let oldLast = before.length; let newLast = after.length;
  while (oldLast > first && newLast > first && before[oldLast - 1] === after[newLast - 1]) { oldLast--; newLast--; }
  const contextStart = Math.max(0, first - 3);
  const contextEnd = Math.min(3, before.length - oldLast, after.length - newLast);
  const diffLines = (lines, from, until, marker, endsWithNewline) => {
    const output = [];
    for (let position = from; position < until; position++) {
      output.push(marker + lines[position]);
      if (!endsWithNewline && position === lines.length - 1) output.push('\\ No newline at end of file');
    }
    return output;
  };
  const prefix = diffLines(before, contextStart, first, ' ', oldEndsWithNewline);
  const suffix = diffLines(before, oldLast, oldLast + contextEnd, ' ', oldEndsWithNewline);
  const hunk = [...prefix, ...diffLines(before, first, oldLast, '-', oldEndsWithNewline), ...diffLines(after, first, newLast, '+', newEndsWithNewline), ...suffix];
  const diff = [`--- a/${index.path}`, `+++ b/${index.path}`, `@@ -${contextStart + 1},${oldLast - contextStart + contextEnd} +${contextStart + 1},${newLast - contextStart + contextEnd} @@`, ...hunk, ''].join('\n');
  // An exact patch containing credential material cannot be exported safely.
  if (clean(diff) !== diff) return null;
  return { status: 'PROPOSED_CHANGE', file: index.path, baseCommit: commit, diff,
    rationale: 'Removing the observed tool registration breaks this specific static capability edge. Whether the tool is needed is a product decision for the reviewer.',
    description: 'Remove this tool from the configured tool list if the agent should not have this capability. Review the behavior change before applying.',
    automaticallyApplied: false, provenance: [evidence] };
}

/** Supports both the object API and (sources, context) for embedders. */
export function analyzeSources(options, context = {}) {
  const input = Array.isArray(options) ? { ...context, sources: options } : (options || {});
  const repository = repositoryName(input.repository || input.repo);
  const commit = String(input.commit || '');
  const sources = (Array.isArray(input.sources) ? input.sources : []).filter(source => source && typeof (source.content ?? source.text) === 'string' && (source.path || source.file))
    .map(source => ({ path: normalizeFile(source.path || source.file), content: source.content ?? source.text })).sort((a, b) => a.path.localeCompare(b.path));
  const allSecrets = sources.flatMap(source => secretCandidates(source.content).flatMap(candidate => [candidate.value, ...(candidate.kind === 'private-key' ? candidate.value.split(/\r?\n/).filter(line => line.trim()) : [])]));
  const clean = value => redactSecrets(value, allSecrets);
  const diagnostics = []; const analyzedFiles = []; const indices = new Map(); const configurations = [];
  const graph = { nodes: [], edges: [] }; const nodes = new Map(); const edges = new Map(); const findings = new Map();
  const diagnostic = (file, code, message) => diagnostics.push({ file, code, message: clean(message), status: 'UNVERIFIED' });
  const evidence = (index, node, rule, customLine = null) => {
    const line = customLine || node?.loc?.start?.line || 1;
    const snippet = index.content.split('\n')[line - 1] || '';
    return { repository, commit, file: index.path, line, snippet: clean(snippet).slice(0, 1200), rule, status: 'OBSERVED' };
  };
  const addNode = (type, file, symbol, label, extras = {}) => {
    const id = `${type.toLowerCase()}-${stableFingerprint([repository, type, file, symbol])}`;
    if (!nodes.has(id)) nodes.set(id, { id, type, label: clean(label), file, symbol: clean(symbol), ...extras });
    return nodes.get(id);
  };
  const addEdge = (from, to, relation, provenance, extras = {}) => {
    const id = `edge-${stableFingerprint([from.id, relation, to.id])}`;
    const previous = edges.get(id);
    const combined = [...(previous?.evidence || []), ...provenance];
    const unique = new Map(combined.map(item => [`${item.file}:${item.line}:${item.rule}`, item]));
    const edge = { id, from: from.id, to: to.id, relation, status: 'OBSERVED', evidence: [...unique.values()], ...extras };
    edges.set(id, edge); return edge;
  };
  const addFinding = finding => {
    const fingerprint = finding.fingerprint || stableFingerprint([repository, finding.rule, finding.evidence, finding.subject || '', finding.capability || '']);
    const item = { id: `finding-${fingerprint}`, fingerprint, sev: 'medium', severity: 'medium', points: 15, mapping: 'Security review', kind: 'code', evidenceType: 'OBSERVED', confidence: 'high', ...finding };
    item.severity = item.sev;
    // Only structured public evidence leaves the analyzer; raw AST and content
    // remain in local analysis memory and are never attached to a finding.
    const previous = findings.get(fingerprint);
    if (previous) {
      const unique = new Map([...(previous.provenance || []), ...(item.provenance || [])].map(proof => [`${proof.file}:${proof.line}:${proof.rule}`, proof]));
      previous.provenance = [...unique.values()];
      previous.occurrences = previous.provenance.filter(proof => proof.rule === item.provenance?.[0]?.rule).length;
    } else findings.set(fingerprint, item);
  };

  for (const source of sources) {
    for (const candidate of secretCandidates(source.content)) {
      const line = source.content.slice(0, candidate.index).split('\n').length;
      const proof = evidence(source, null, 'secret-literal', line);
      addFinding({ rule: 'secret-literal', subject: `${candidate.name}:${candidate.kind}`, capability: 'source-credential', sev: candidate.kind === 'aws-access-key' ? 'medium' : 'high', points: 22,
        title: 'Likely credential is present in repository source', detail: `A ${candidate.kind} pattern appears in source. Credential validity has not been tested.`,
        whatCanHappen: 'Someone with access to this source may be able to copy a credential and use the associated service if the credential is valid.',
        whyItMatters: 'A valid exposed credential can grant permissions outside the application.',
        proven: 'A credential-shaped literal was found in the specified repository source.', notProven: 'Heimdall did not validate the credential, its permissions, or whether it has been used.',
        fix: 'If this is a real credential, revoke or rotate it and load the replacement from a secret manager or environment configuration. Removing the line alone does not revoke a credential.',
        evidence: source.path, line, snippet: proof.snippet, provenance: [proof], confidence: candidate.confidence,
        reasoning: candidate.kind === 'credential-literal' ? 'The literal is assigned to a credential-like name and has high character entropy.' : 'The literal matches a supported provider credential format.',
        credentialType: candidate.kind, mapping: 'CWE-798 · Hard-coded credential', kind: 'secret', secretStatus: 'LIKELY_SECRET' });
    }
    if (SOURCE_EXTENSIONS.test(source.path)) {
      try {
        const plugins = /\.ts$/i.test(source.path) ? ['typescript'] : /\.tsx$/i.test(source.path) ? ['typescript', 'jsx'] : ['jsx'];
        const ast = parse(source.content, { sourceType: 'unambiguous', plugins, errorRecovery: false });
        indices.set(source.path, indexSource(source, ast)); analyzedFiles.push(source.path);
      } catch (error) {
        const location = error.loc ? ` at line ${error.loc.line}, column ${error.loc.column + 1}` : '';
        diagnostic(source.path, 'PARSE_ERROR', `Source parser failed${location} (${error.reasonCode || 'syntax error'}); capability analysis is unavailable for this file.`);
      }
    } else if (/\.json$/i.test(source.path)) {
      try {
        const config = JSON.parse(source.content);
        const locationAst = parse(`(${source.content}\n)`, { sourceType: 'script' }).program.body[0].expression;
        configurations.push({ ...source, config, locationAst }); analyzedFiles.push(source.path);
      }
      catch (error) {
        const position = String(error.message).match(/position (\d+)/)?.[1];
        diagnostic(source.path, 'PARSE_ERROR', `JSON parser failed${position ? ` at character ${position}` : ''}; configuration analysis is unavailable for this file.`);
      }
    } else diagnostic(source.path, 'UNSUPPORTED_LANGUAGE', 'This file received text secret detection only. Structural capability analysis supports JavaScript, TypeScript, and JSON configuration.');
  }

  const toolOperations = new Map(); const agentRegistrations = [];
  function analyzeTool(resolved, toolNode) {
    if (toolOperations.has(toolNode.id)) return;
    toolOperations.set(toolNode.id, []);
    const index = resolved.bodyIndex || resolved.index;
    const shadowed = new Set();
    for (const parameter of resolved.body.params || []) walk(parameter, node => { if (node.type === 'Identifier') shadowed.add(node.name); });
    walk(resolved.body.body, node => { if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier') shadowed.add(node.id.name); });
    walk(resolved.body.body, node => {
      // Do not claim operations in a nested callback/function are directly
      // implemented by the enclosing tool without modeling that invocation.
      if (['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression'].includes(node.type)) return false;
      const credential = !isShadowedAt(index, node, 'process') && credentialReference(node);
      if (credential) {
        const reference = addNode('CredentialReference', index.path, credential, credentialType(credential), { credentialType: credential });
        addEdge(toolNode, reference, 'USES', [evidence(index, node, 'tool-credential-reference')]);
      }
      const operation = sensitiveOperation(index, node, indices, shadowed);
      if (!operation) return;
      const proof = evidence(index, node, 'tool-sensitive-operation');
      const resource = addNode('SensitiveResource', index.path, `${resolved.name}:${operation.action}`, operation.label, { category: operation.category });
      addEdge(toolNode, resource, operation.relation, [proof]);
      toolOperations.get(toolNode.id).push({ resource, operation, proof });
      if (operation.service?.binding) {
        const binding = operation.service.binding;
        for (const [argumentPosition, argument] of (binding.value.arguments || []).entries()) walk(argument, value => {
          const name = credentialReference(value);
          if (!name) return;
          const reference = addNode('CredentialReference', binding.index.path, name, credentialType(name), { credentialType: name });
          const relationship = operation.service.kind === 'stripe' && argumentPosition === 0 && value === unwrap(argument) ? 'AUTHENTICATES_WITH' : 'USES';
          addEdge(toolNode, reference, relationship, [proof, evidence(binding.index, value, 'service-credential-reference')]);
        });
      }
    });
  }

  for (const index of indices.values()) {
    for (const definition of index.definitions.values()) {
      const value = definition.value;
      if (!value || !['CallExpression', 'NewExpression'].includes(value.type) || !importRole(index, value.callee, ['Agent', 'createAgent', 'createReactAgent'], AGENT_IMPORTS)) continue;
      const configResult = resolveExpression(index, value.arguments[0], indices);
      const config = properties(configResult.node);
      if (!config.size) { diagnostic(index.path, 'UNRESOLVED_AGENT_CONFIG', `Agent ${definition.name} uses a configuration outside the supported explicit object patterns.`); continue; }
      const agentLabel = literal(config.get('name')) || definition.name;
      const agent = addNode('Agent', index.path, definition.name, agentLabel);
      index.agents.push({ symbol: definition.name, node: agent });
      const arrayResult = resolveExpression(configResult.index, config.get('tools'), indices);
      const array = arrayResult.node;
      if (!array) continue;
      if (array.type !== 'ArrayExpression') { diagnostic(index.path, 'UNRESOLVED_TOOL_LIST', `Agent ${definition.name} has a tool list that cannot be resolved statically.`); continue; }
      for (const element of array.elements) {
        if (!element || element.type !== 'Identifier') { diagnostic(arrayResult.index.path, 'UNRESOLVED_TOOL', `Agent ${definition.name} contains a tool entry outside supported named function/import patterns.`); continue; }
        const resolved = callable(resolveDefinition(arrayResult.index, element.name, indices), indices);
        if (!resolved) { diagnostic(arrayResult.index.path, 'UNRESOLVED_TOOL', `Tool ${element.name} could not be resolved to a supported source function. No capability edge was inferred.`); continue; }
        const tool = addNode('Tool', resolved.index.path, resolved.name, resolved.label);
        const proof = evidence(arrayResult.index, element, 'agent-tool-registration');
        const definitionProof = evidence(resolved.index, resolved.node, 'tool-definition');
        addEdge(agent, tool, 'CAN_CALL', [proof, definitionProof]);
        analyzeTool(resolved, tool);
        agentRegistrations.push({ agent, tool, index: arrayResult.index, array, element, proof });
      }
    }
  }

  // Identify input only at an explicit run/invoke call on a resolved agent.
  // Co-occurrence of req.body and an agent elsewhere in a file creates no edge.
  for (const index of indices.values()) {
    const agentSymbols = new Map(index.agents.map(item => [item.symbol, item.node]));
    for (const [local, imported] of index.imports) {
      const target = resolveModule(index.path, imported.source, indices);
      const exported = target?.exports.get(imported.imported);
      const original = typeof exported === 'string' && target.agents.find(agent => agent.symbol === exported);
      if (original) agentSymbols.set(local, original.node);
    }
    for (const definition of index.definitions.values()) {
      if (definition.value?.type !== 'Identifier') continue;
      const resolved = resolveDefinition(index, definition.name, indices);
      const original = resolved?.index.agents.find(agent => agent.symbol === resolved.name);
      if (original) agentSymbols.set(definition.name, original.node);
    }
    walk(index.ast, node => {
      if (node.type !== 'CallExpression') return;
      const parts = memberParts(node.callee);
      const memberRun = parts?.length === 2 && ['run', 'invoke', 'ainvoke'].includes(parts[1]) && agentSymbols.has(parts[0]) && !isShadowedAt(index, node, parts[0]);
      const sdkRun = importRole(index, node.callee, ['run'], AGENT_IMPORTS) && !isShadowedAt(index, node, parts?.[0]) && node.arguments[0]?.type === 'Identifier' && agentSymbols.has(node.arguments[0].name) && !isShadowedAt(index, node, node.arguments[0].name);
      if (!memberRun && !sdkRun) return;
      const agentSymbol = memberRun ? parts[0] : node.arguments[0].name;
      const agent = agentSymbols.get(agentSymbol);
      for (const argument of memberRun ? node.arguments : node.arguments.slice(1)) walk(argument, value => {
        // The result of an arbitrary helper and the contents of an unexecuted
        // callback are not proven to carry request data into the agent.
        if (['CallExpression', 'NewExpression', 'FunctionExpression', 'ArrowFunctionExpression', 'FunctionDeclaration'].includes(value.type)) return false;
        const access = memberParts(value);
        if (!access || access.length < 2 || !['req', 'request'].includes(access[0]) || !['body', 'query', 'params'].includes(access[1])) return;
        const inputNode = addNode('InputSource', index.path, `${agentSymbol}:${access.join('.')}`, `${access.join('.')} request input`);
        addEdge(inputNode, agent, 'RECEIVES_INPUT_FROM', [evidence(index, value, 'agent-external-input')]);
        return false;
      });
    });
  }

  for (const source of configurations) {
    const servers = source.config?.mcpServers || source.config?.mcp?.servers;
    if (!servers || typeof servers !== 'object' || Array.isArray(servers)) continue;
    const rootProperties = properties(source.locationAst);
    const serversAst = rootProperties.get('mcpServers') || properties(rootProperties.get('mcp')).get('servers');
    const serverProperties = properties(serversAst);
    for (const [name, serverConfig] of Object.entries(servers)) {
      if (!serverConfig || typeof serverConfig !== 'object' || Array.isArray(serverConfig)) continue;
      const serverAst = serverProperties.get(name);
      if (!serverAst) continue;
      const fieldNodes = properties(serverAst);
      const server = addNode('MCPServer', source.path, `mcpServers.${name}`, name);
      if (typeof serverConfig.command === 'string') {
        const command = addNode('ExternalService', source.path, `mcpServers.${name}.command`, `MCP command: ${serverConfig.command}`);
        addEdge(server, command, 'CAN_TRIGGER', [evidence(source, fieldNodes.get('command'), 'mcp-command-configuration')]);
      }
      if (typeof serverConfig.url === 'string') {
        const transport = addNode('ExternalService', source.path, `mcpServers.${name}.url`, 'Configured remote MCP endpoint');
        addEdge(server, transport, 'USES', [evidence(source, fieldNodes.get('url'), 'mcp-url-configuration')]);
      }
      const envNodes = properties(fieldNodes.get('env'));
      for (const [variable, envValue] of Object.entries(serverConfig.env || {})) {
        if (!CREDENTIAL_NAME.test(variable) || typeof envValue !== 'string') continue;
        const reference = addNode('CredentialReference', source.path, `mcpServers.${name}.env.${variable}`, credentialType(variable), { credentialType: variable });
        addEdge(server, reference, 'USES', [evidence(source, envNodes.get(variable), 'mcp-credential-configuration')]);
      }
      if (Array.isArray(serverConfig.tools)) {
        for (const [position, value] of serverConfig.tools.entries()) {
          const toolName = typeof value === 'string' ? value : value?.name;
          if (typeof toolName !== 'string') continue;
          const tool = addNode('Tool', source.path, `mcpServers.${name}.tools.${toolName}`, toolName, { configurationOnly: true });
          const toolAst = fieldNodes.get('tools')?.elements?.[position];
          addEdge(server, tool, 'CAN_CALL', [evidence(source, toolAst, 'mcp-tool-configuration')]);
        }
      }
    }
  }

  graph.nodes = [...nodes.values()].sort((a, b) => a.id.localeCompare(b.id));
  graph.edges = [...edges.values()].sort((a, b) => a.id.localeCompare(b.id));
  const paths = derivePaths(graph, { repository, commit });
  if (paths.length >= 250) diagnostic('', 'PATH_LIMIT', 'Static capability traversal reached the 250-path limit. Additional paths may exist.');
  for (const registration of agentRegistrations) {
    for (const { resource, operation, proof } of toolOperations.get(registration.tool.id) || []) {
      const relatedPaths = paths.filter(path => path.nodeIds.includes(registration.agent.id) && path.nodeIds.includes(registration.tool.id) && path.nodeIds.at(-1) === resource.id);
      const externalPath = relatedPaths.find(path => path.prerequisites.externalInput);
      const [whatCanHappen, whyItMatters] = impact(operation.category);
      const provenance = [...(externalPath?.provenance || []), registration.proof, proof];
      const unique = new Map(provenance.map(item => [`${item.file}:${item.line}:${item.rule}`, item]));
      const patch = removalPatch(registration.index, registration.array, registration.element, clean, registration.proof, commit);
      const risk = ['financial-action', 'record-deletion', 'process-execution', 'dynamic-code', 'file-deletion'].includes(operation.category) ? 'high' : 'medium';
      addFinding({ rule: 'agent-sensitive-capability', subject: registration.agent.id, capability: `${registration.tool.id}:${resource.id}`, sev: risk, points: externalPath ? 28 : 21,
        title: capabilityTitle(registration.agent.label, operation.category),
        detail: `The agent explicitly registers ${registration.tool.label}. Its resolved implementation contains ${operation.action}.${externalPath ? ' Request input is passed to this agent in source.' : ' No supported external-input call was linked to this agent.'}`,
        whatCanHappen, whyItMatters,
        proven: `Source registers ${registration.tool.label} on ${registration.agent.label} and contains the ${operation.action} expression inside the resolved tool function.${externalPath ? ' Source also passes request input into this agent.' : ''}`,
        notProven: 'Heimdall did not execute the agent or tool, prove an unauthorized action, test prompt injection, or establish whether authorization controls prevent misuse. Conditional branches and other runtime controls can affect execution.',
        fix: `Remove ${registration.tool.label} from this agent's configured tools if this capability is not part of its intended responsibility. If it is required, review the implementation and add authorization appropriate to the operation.`,
        evidence: registration.proof.file, line: registration.proof.line, snippet: registration.proof.snippet, provenance: [...unique.values()],
        evidenceType: 'DERIVED', kind: 'capability', mapping: 'OWASP LLM06 · Excessive agency review', relatedAgent: registration.agent.label, relatedTool: registration.tool.label,
        relatedPermission: operation.action, confidence: 'high', reasoning: 'A deterministic traversal links an explicit agent tool registration to a supported sensitive API call in the resolved function. This establishes static capability, not runtime exploitability.',
        staticStatus: 'REACHABLE', staticReachability: 'REACHABLE', exploitStatus: 'UNVERIFIED', exploit: 'UNVERIFIED', pathId: (externalPath || relatedPaths[0])?.id, pathIds: relatedPaths.map(path => path.id), ...(patch ? { patch } : {}) });
    }
  }

  // Standalone source sinks remain observations, not claims about user control.
  for (const index of indices.values()) {
    const localNames = new Set();
    walk(index.ast, node => { if (node.type === 'FunctionDeclaration' && node.id) localNames.add(node.id.name); });
    walk(index.ast, node => {
      const operation = sensitiveOperation(index, node, indices, localNames);
      if (!operation) return;
      const proof = evidence(index, node, 'sensitive-source-operation');
      const [whatCanHappen, whyItMatters] = impact(operation.category);
      addFinding({ rule: 'sensitive-source-operation', subject: `${enclosingSymbol(index, node)}:${operation.action}`, capability: operation.category, sev: 'medium', points: 10,
        title: `${operation.label} is present in source`, detail: `Source contains ${operation.action}. Its inputs and runtime authorization were not evaluated.`,
        whatCanHappen: whatCanHappen.replace('The configured tool', 'The source'), whyItMatters,
        proven: `The supported source expression ${operation.action} is present in this file.`, notProven: 'No untrusted-input data flow, execution, authorization bypass, or exploitable vulnerability was demonstrated.',
        fix: 'Review who can reach this operation and validate the authorization and input constraints required by its intended behavior.',
        evidence: index.path, line: proof.line, snippet: proof.snippet, provenance: [proof], mapping: 'Sensitive operation review', confidence: 'high', reasoning: 'The expression resolves to a supported library import, constructor, or built-in API.' });
    });
  }

  const dependencies = Array.isArray(input.dependencies) ? input.dependencies : [];
  for (const dependency of dependencies) {
    if (!dependency?.name) continue;
    addNode('Dependency', dependency.file || '', `${dependency.ecosystem}:${dependency.name}:${dependency.version || 'unresolved'}`, `${dependency.name}${dependency.version ? `@${dependency.version}` : ' (version unresolved)'}`, {
      package: clean(dependency.name), version: dependency.version || null, ecosystem: dependency.ecosystem || '', status: dependency.version ? 'OBSERVED' : 'UNVERIFIED',
    });
  }
  const advisories = input.osv?.vulnerabilities || input.osv?.matches || [];
  for (const advisory of Array.isArray(advisories) ? advisories : []) {
    const dependency = advisory.dependency;
    if (!dependency?.file || !dependency.name || !dependency.version || !advisory.id) continue;
    const proof = { repository, commit, file: dependency.file, line: Number.isInteger(dependency.line) && dependency.line > 0 ? dependency.line : 1,
      snippet: clean(`${dependency.name}@${dependency.version} (${dependency.ecosystem})`), rule: 'osv-dependency-advisory', status: 'OBSERVED' };
    const declaredSeverity = advisory.databaseSpecific?.severity || advisory.database_specific?.severity || advisory.affected?.find(item => item.database_specific?.severity)?.database_specific?.severity;
    const severityLabels = { critical: 'critical', high: 'high', moderate: 'medium', medium: 'medium', low: 'low' };
    let localSeverity = severityLabels[String(declaredSeverity || '').toLowerCase()];
    let severitySource = localSeverity ? 'OSV_DATABASE_METADATA' : 'UNKNOWN';
    if (!localSeverity) {
      const numericScore = (advisory.severity || []).find(item => /^(?:\d(?:\.\d+)?|10(?:\.0+)?)$/.test(String(item.score)))?.score;
      if (numericScore !== undefined) {
        const score = Number(numericScore);
        localSeverity = score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : 'low';
        severitySource = 'OSV_NUMERIC_SCORE';
      }
    }
    localSeverity ||= 'medium';
    addFinding({ rule: 'osv-dependency-advisory', subject: `${dependency.ecosystem}:${dependency.name}`, capability: advisory.id, sev: localSeverity, points: 20, kind: 'dependency',
      title: `${dependency.name}@${dependency.version} matches ${advisory.id}`, detail: clean(advisory.summary || 'OSV returned a vulnerability advisory for this resolved package/version.'),
      whatCanHappen: 'This dependency version is listed by OSV as affected by a known vulnerability. Actual application impact depends on how the dependency is used.',
      whyItMatters: 'A vulnerable dependency can expose the application to the advisory conditions when the affected functionality is reachable.',
      proven: 'A resolved package/version from this repository was queried and OSV returned this advisory.', notProven: 'Heimdall did not establish runtime reachability or exploit this dependency vulnerability.',
      fix: 'Review the advisory affected ranges and upgrade to a version outside those ranges, then rescan the changed repository state.',
      evidence: dependency.file, line: proof.line, snippet: proof.snippet, provenance: [proof], mapping: 'Known vulnerable dependency',
      dependency: { name: clean(dependency.name), version: clean(dependency.version), ecosystem: clean(dependency.ecosystem || ''), file: dependency.file },
      vulnerabilityId: clean(advisory.id), advisory: clean(advisory.id), affectedRanges: advisory.affectedRanges || [], source: advisory.source || `https://osv.dev/vulnerability/${encodeURIComponent(advisory.id)}`,
      rawSeverity: advisory.severity || [], severitySource,
      confidence: 'high', reasoning: `OSV matched a specific resolved package version; application exploitability remains unverified.${severitySource === 'UNKNOWN' ? ' Advisory severity could not be established; medium is a local review priority.' : ''}` });
  }
  graph.nodes = [...nodes.values()].sort((a, b) => a.id.localeCompare(b.id));
  const result = [...findings.values()].sort((a, b) => ({ critical: 4, high: 3, medium: 2, low: 1, info: 0 }[b.sev] - { critical: 4, high: 3, medium: 2, low: 1, info: 0 }[a.sev]) || b.points - a.points || a.id.localeCompare(b.id));
  const sanitizePublic = value => {
    if (typeof value === 'string') return clean(value);
    if (Array.isArray(value)) return value.map(sanitizePublic);
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, sanitizePublic(item)]));
    return value;
  };
  return sanitizePublic({ engineVersion: ENGINE_VERSION, findings: result, graph, paths, pathAnalysisComplete: paths.length < 250, diagnostics, analyzedFiles, secretAnalyzedFiles: sources.map(source => source.path),
    sanitizedDependencies: dependencies, sanitizedOSV: input.osv || { vulnerabilities: [] }, supportedLanguages: ['JavaScript', 'TypeScript', 'JSON configuration'] });
}
