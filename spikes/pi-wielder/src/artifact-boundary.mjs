export function assertArtifactNotSerialized(input) {
  if (input === null || typeof input !== 'object' || Array.isArray(input)
      || Object.getPrototypeOf(input) !== Object.prototype
      || Object.keys(input).sort().join(',') !== 'artifact,output') {
    throw new TypeError('artifact boundary requires one exact plain object');
  }
  const { output, artifact } = input;
  if (typeof output !== 'string' || typeof artifact !== 'string' || artifact.length === 0) {
    throw new TypeError('artifact boundary requires exact string inputs and a non-empty artifact');
  }
  const fragments = artifact.length >= 400
    ? [artifact, artifact.slice(0, 200), artifact.slice(-200)]
    : [artifact];
  if (fragments.some((fragment) => output.includes(fragment))) {
    throw new Error('direct artifact serialization detected in model output');
  }
  return true;
}
