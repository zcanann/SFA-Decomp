/* Reduced GC/1.3 compiler reproducer, not a proposed game function. */
typedef short s16;
typedef float f32;

int sampleRootDelta(s16* moveSamples, s16* blendSamples, int segmentCount, f32 currentProgress, f32 moveRootScale,
                    f32 blendScale, f32 moveWeight, f32 blendWeight, f32 targetTravelDistance, f32* phaseOut,
                    f32 segmentStartDistance, f32 segmentEndDistance) {
    s16* axisSamples;
    f32 blendDistanceDelta;
    f32 moveDistanceDelta;
    int sampleIndex;
    f32 curveProgress;
    f32 phase;
    f32 phaseStep;
    f32 curveFraction;
    f32 sampleCount;
    int foundPhase;

    sampleCount = segmentCount;
    phaseStep = 1.0f / sampleCount;
    curveProgress = sampleCount * currentProgress;
    sampleIndex = curveProgress;
    curveFraction = curveProgress - sampleIndex;
    phase = phaseStep - (phaseStep * curveFraction);
    foundPhase = 0;
    do {
        if (segmentEndDistance > targetTravelDistance) {
            phase -=
                (phaseStep * (segmentEndDistance - targetTravelDistance)) / (segmentEndDistance - segmentStartDistance);
            foundPhase = 1;
        } else {
            sampleIndex++;
            if (sampleIndex >= segmentCount) {
                sampleIndex = 0;
            }
            segmentStartDistance = segmentEndDistance;
            if (blendSamples != 0) {
                axisSamples = &moveSamples[sampleIndex];
                moveDistanceDelta = moveRootScale * ((f32)axisSamples[1] - axisSamples[0]);
                axisSamples = &blendSamples[sampleIndex];
                blendDistanceDelta = blendScale * ((f32)axisSamples[1] - axisSamples[0]);
                segmentEndDistance += (moveDistanceDelta * moveWeight) + (blendDistanceDelta * blendWeight);
            } else {
                axisSamples = &moveSamples[sampleIndex];
                segmentEndDistance += moveRootScale * ((f32)axisSamples[1] - axisSamples[0]);
            }
            phase += phaseStep;
        }
    } while (!foundPhase);

    if (phaseOut != 0) {
        *phaseOut = phase;
    }
    return 1;
}
