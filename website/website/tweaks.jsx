// Tweaks panel — accent color and a few subtle layout knobs.
// Theme is handled by the in-page nav button (vanilla JS + localStorage)
// because it's a user-facing toggle, not a designer-facing default.

const TWEAK_DEFAULTS = /*EDITMODE-BEGIN*/{
  "accent": "#E94B3C",
  "tintDiag": true,
  "showPulseRule": true
}/*EDITMODE-END*/;

function TweaksApp() {
  const [t, setTweak] = useTweaks(TWEAK_DEFAULTS);

  React.useEffect(() => {
    document.documentElement.style.setProperty("--accent", t.accent);
  }, [t.accent]);

  React.useEffect(() => {
    // Toggle the diag-tinted wordmark across all .wm__diag spans.
    document
      .querySelectorAll(".wm__diag")
      .forEach((el) => {
        el.style.color = t.tintDiag ? "var(--accent)" : "inherit";
      });
  }, [t.tintDiag]);

  React.useEffect(() => {
    document.querySelectorAll(".section__pulse").forEach((el) => {
      el.style.display = t.showPulseRule ? "block" : "none";
    });
  }, [t.showPulseRule]);

  return (
    <TweaksPanel title="Tweaks">
      <TweakSection label="Brand" />
      <TweakColor
        label="Accent"
        value={t.accent}
        options={["#E94B3C", "#0FA678", "#F2A93B", "#5C9BFF", "#B856D9"]}
        onChange={(v) => setTweak("accent", v)}
      />
      <TweakToggle
        label="Tint 'diag' in wordmark"
        value={t.tintDiag}
        onChange={(v) => setTweak("tintDiag", v)}
      />
      <TweakSection label="Layout" />
      <TweakToggle
        label="EKG rule on section heads"
        value={t.showPulseRule}
        onChange={(v) => setTweak("showPulseRule", v)}
      />
    </TweaksPanel>
  );
}

const root = ReactDOM.createRoot(document.getElementById("tweaks-root"));
root.render(<TweaksApp />);
