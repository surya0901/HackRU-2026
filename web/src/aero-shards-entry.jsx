import { createRoot } from 'react-dom/client';

import AeroShards from './AeroShards';
import HeadlineReel from './HeadlineReel';

const mount = document.querySelector('#aeroShardsMount');

if (mount) {
  const root = createRoot(mount);
  const render = () => {
    const dark = document.documentElement.classList.contains('dark');
    root.render(
      <AeroShards
      backgroundColor={dark ? '#181818' : '#ffffff'}
      shardColor={dark ? '#BF9B30' : '#91641a'}
      accentColor={dark ? '#fff8df' : '#fff0c2'}
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
      glow={dark ? 1.35 : 0.9}
      edgeSoftness={dark ? 0.7 : 1.25}
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
  };

  render();
  new MutationObserver(render).observe(document.documentElement, {
    attributes: true,
    attributeFilter: ['class']
  });
}

const headlineMount = document.querySelector('#glyphLotteryHeadline');

if (headlineMount) {
  createRoot(headlineMount).render(
    <HeadlineReel text="Understand your project before you ship it." />
  );
}
