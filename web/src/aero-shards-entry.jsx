import { createRoot } from 'react-dom/client';

import AeroShards from './AeroShards';

const mount = document.querySelector('#aeroShardsMount');

if (mount) {
  createRoot(mount).render(
    <AeroShards
      backgroundColor="#ffffff"
      shardColor="#91641a"
      accentColor="#fff0c2"
      placement="full"
      flow="stream"
      material="chrome"
      detail="bold"
      effect="none"
      scale={0.9}
      spread={1.1}
      depth={1}
      speed={0.6}
      spin={0.7}
      interaction="repel"
      density={0.85}
      shardSize={1.25}
      stretch={1}
      turbulence={0.55}
      glow={0.9}
      edgeSoftness={1.25}
      bloom={0}
      grain={0}
      chromaticAberration={0}
      transitionDuration={1}
      interactionRadius={1.5}
      interactionStrength={0.32}
      rippleIntensity={0.6}
      holdToGather
      onError={() => mount.classList.add('aero-shards-unavailable')}
    />
  );
}
