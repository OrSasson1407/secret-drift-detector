export function SeverityBadge({ value }: { value: string }) {
  const colors: Record<string, { bg: string, text: string, border: string, shadow: string }> = {
    CRITICAL: { bg: "rgba(239, 68, 68, 0.15)", text: "#fca5a5", border: "rgba(239, 68, 68, 0.4)", shadow: "0 0 10px rgba(239, 68, 68, 0.2)" },
    HIGH:     { bg: "rgba(249, 115, 22, 0.15)", text: "#fdba74", border: "rgba(249, 115, 22, 0.4)", shadow: "0 0 10px rgba(249, 115, 22, 0.2)" },
    WARN:     { bg: "rgba(234, 179, 8, 0.15)", text: "#fde047", border: "rgba(234, 179, 8, 0.4)", shadow: "0 0 10px rgba(234, 179, 8, 0.2)" },
    INFO:     { bg: "rgba(59, 130, 246, 0.15)", text: "#93c5fd", border: "rgba(59, 130, 246, 0.4)", shadow: "0 0 10px rgba(59, 130, 246, 0.2)" },
  };

  const style = colors[value.toUpperCase()] || colors.INFO;

  return (
    <span className="px-2.5 py-0.5 rounded-md text-xs font-bold tracking-wider backdrop-blur-sm transition-all duration-300"
          style={{ background: style.bg, color: style.text, border: `1px solid ${style.border}`, boxShadow: style.shadow }}>
      {value.toUpperCase()}
    </span>
  );
}

export function KindBadge({ value }: { value: string }) {
  const isMissing = value.toLowerCase() === "missing";
  return (
    <span className="px-2.5 py-0.5 rounded-md text-xs font-bold tracking-wider"
          style={{ 
            background: isMissing ? "rgba(168, 85, 247, 0.15)" : "rgba(14, 165, 233, 0.15)", 
            color: isMissing ? "#d8b4fe" : "#7dd3fc", 
            border: `1px solid ${isMissing ? "rgba(168, 85, 247, 0.4)" : "rgba(14, 165, 233, 0.4)"}` 
          }}>
      {value.toUpperCase()}
    </span>
  );
}
