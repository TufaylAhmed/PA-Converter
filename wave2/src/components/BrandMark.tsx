type Props = { size?: number; className?: string }

/** Crisp PA mark used in sidebar + favicon-style surfaces */
export function BrandMark({ size = 36, className }: Props) {
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 64 64"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden
    >
      <defs>
        <linearGradient id="pa-mark-bg" x1="8" y1="4" x2="56" y2="60" gradientUnits="userSpaceOnUse">
          <stop stopColor="#3A3A3C" />
          <stop offset="1" stopColor="#111113" />
        </linearGradient>
      </defs>
      <rect width="64" height="64" rx="16" fill="url(#pa-mark-bg)" />
      <path
        d="M16 44V20h12.2c6.1 0 10 3.4 10 8.7 0 5.4-4 8.9-10.1 8.9H23.4V44H16zm7.4-12h4.4c2.6 0 4.1-1.4 4.1-3.5s-1.5-3.4-4.1-3.4h-4.4V32zM39.2 44l8.4-24h7.7L63.8 44h-7.6l-1.4-4.4H45.5L44.1 44h-4.9zm9.6-10h5.4l-2.7-8.4-2.7 8.4z"
        fill="#F5F5F7"
      />
    </svg>
  )
}
