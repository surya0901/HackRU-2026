import { useEffect, useRef, useState } from 'react';

const LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';

function randomGlyph(target) {
  if (!/[a-z]/i.test(target)) return target;
  const pool = target === target.toUpperCase() ? LETTERS : LOWERCASE;
  return pool[Math.floor(Math.random() * pool.length)];
}

export default function HeadlineReel({ text }) {
  const rootRef = useRef(null);
  const [glyphs, setGlyphs] = useState(() => [...text]);
  const [settled, setSettled] = useState(() => [...text].map(char => char === ' '));

  useEffect(() => {
    const root = rootRef.current;
    if (!root) return undefined;

    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    let played = false;
    let timers = [];

    const play = () => {
      if (played || reduceMotion) return;
      played = true;
      const characters = [...text];
      const animatedIndexes = characters
        .map((char, index) => (/[a-z]/i.test(char) ? index : null))
        .filter(index => index !== null);

      setSettled(characters.map(char => char === ' '));

      animatedIndexes.forEach((characterIndex, order) => {
        const spin = window.setInterval(() => {
          setGlyphs(current => current.map((char, index) => (
            index === characterIndex ? randomGlyph(characters[index]) : char
          )));
        }, 42);

        const stop = window.setTimeout(() => {
          window.clearInterval(spin);
          setGlyphs(current => current.map((char, index) => (
            index === characterIndex ? characters[index] : char
          )));
          setSettled(current => current.map((value, index) => (
            index === characterIndex ? true : value
          )));
        }, 390 + (order * 38));

        timers.push(spin, stop);
      });
    };

    if (reduceMotion) {
      setGlyphs([...text]);
      setSettled([...text].map(() => true));
      return undefined;
    }

    const observer = new IntersectionObserver(entries => {
      if (entries.some(entry => entry.isIntersecting)) {
        play();
        observer.disconnect();
      }
    }, { threshold: 0.55 });

    observer.observe(root);
    return () => {
      observer.disconnect();
      timers.forEach(timer => {
        window.clearInterval(timer);
        window.clearTimeout(timer);
      });
    };
  }, [text]);

  let glyphIndex = 0;
  const words = text.split(/(\s+)/).map((token, tokenIndex) => {
    if (/^\s+$/.test(token)) {
      glyphIndex += token.length;
      return <span className="headline-reel__space" aria-hidden="true" key={`space-${tokenIndex}`}> </span>;
    }

    const letters = [...token].map(() => {
      const index = glyphIndex;
      glyphIndex += 1;
      return (
        <span
          className={`headline-reel__glyph${settled[index] ? ' is-settled' : ' is-spinning'}`}
          key={`${index}-${text[index]}`}
        >
          {glyphs[index]}
        </span>
      );
    });

    return <span className="headline-reel__word" aria-hidden="true" key={`word-${tokenIndex}`}>{letters}</span>;
  });

  return (
    <span ref={rootRef} className="headline-reel" aria-label={text}>
      {words}
    </span>
  );
}
