/** Minimal line icons. Inline SVG — no icon dependency. */

type P = { className?: string };
const base = {
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.6,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
};

export const Tick = ({ className = "tick" }: P) => (
  <svg className={className} viewBox="0 0 24 24" aria-hidden="true" {...base}>
    <path d="M4 12.5 9.5 18 20 6.5" />
  </svg>
);

export const Mark = ({ className = "brand-mark" }: P) => (
  <svg className={className} viewBox="0 0 24 24" aria-hidden="true">
    <rect x="1.6" y="1.6" width="20.8" height="20.8" rx="6.4" fill="#0D0E0A" />
    <path d="M7 12.4 10.6 16 17.2 8.6" fill="none" stroke="#C8F04B" strokeWidth="2.1"
      strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

export const Lock = ({ className }: P) => (
  <svg className={className} viewBox="0 0 24 24" aria-hidden="true" {...base}>
    <rect x="4.5" y="10.5" width="15" height="10" rx="3" />
    <path d="M8.2 10.5V7.6a3.8 3.8 0 0 1 7.6 0v2.9" />
  </svg>
);

export const Device = ({ className }: P) => (
  <svg className={className} viewBox="0 0 24 24" aria-hidden="true" {...base}>
    <rect x="3" y="4" width="18" height="13" rx="2.4" />
    <path d="M9 20.5h6" />
  </svg>
);

export const Server = ({ className }: P) => (
  <svg className={className} viewBox="0 0 24 24" aria-hidden="true" {...base}>
    <rect x="3.5" y="4" width="17" height="6.5" rx="2" />
    <rect x="3.5" y="13.5" width="17" height="6.5" rx="2" />
    <path d="M7.5 7.25h.01M7.5 16.75h.01" />
  </svg>
);

export const Shield = ({ className }: P) => (
  <svg className={className} viewBox="0 0 24 24" aria-hidden="true" {...base}>
    <path d="M12 3 5 6v6c0 4.4 3 7.9 7 9 4-1.1 7-4.6 7-9V6l-7-3Z" />
    <path d="M9 12.2 11.2 14.5 15.4 10" />
  </svg>
);

export const Ledger = ({ className }: P) => (
  <svg className={className} viewBox="0 0 24 24" aria-hidden="true" {...base}>
    <rect x="4" y="3.5" width="16" height="17" rx="2.4" />
    <path d="M8 8.5h8M8 12.5h8M8 16.5h4" />
  </svg>
);

export const ArrowDown = ({ className }: P) => (
  <svg className={className} viewBox="0 0 24 24" aria-hidden="true" {...base}>
    <path d="M12 4.5v15M6.5 14l5.5 5.5L17.5 14" />
  </svg>
);

export const ArrowRight = ({ className }: P) => (
  <svg className={className} viewBox="0 0 24 24" aria-hidden="true" {...base}>
    <path d="M4.5 12h15M14 6.5l5.5 5.5L14 17.5" />
  </svg>
);

export const Cross = ({ className }: P) => (
  <svg className={className} viewBox="0 0 24 24" aria-hidden="true" {...base}>
    <path d="M7 7l10 10M17 7 7 17" />
  </svg>
);
