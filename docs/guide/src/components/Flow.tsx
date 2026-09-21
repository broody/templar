type Step = { title: string; detail: string }

export function Flow({ steps, caption }: { steps: [Step, Step, Step]; caption: string }) {
  return (
    <figure className="guide-diagram" aria-label={caption}>
      <div className="guide-flow">
        {steps.flatMap((step, index) => [
          ...(index ? [<span className="guide-arrow" aria-hidden="true" key={`arrow-${index}`}>→</span>] : []),
          <div className="guide-node" key={step.title}>
            <div className="guide-step">0{index + 1}</div>
            <strong>{step.title}</strong>
            <span>{step.detail}</span>
          </div>,
        ])}
      </div>
      <figcaption>{caption}</figcaption>
    </figure>
  )
}
