#!/usr/bin/env python3
"""Check wall-search camera storage and path bounds with native pointers."""

from pathlib import Path
import subprocess
import tempfile
import unittest

from brute_match import find_function_body
from test_camera_update_storage import records

ROOT = Path(__file__).resolve().parents[1]
SERVICES = r"""
#include <math.h>
static CameraModeNormalState state;
static CameraModeNormalState* gCameraModeNormalState = &state;
static f32 gCameraModeNormalScaledTimeDelta = 1.0f;
static GameObject target;
static f32 origin[3];
static int answers[12], answerCount, probes, segments, rejectPositiveSegment;
static int ticks, previousPositions;
static u32 OSGetTick(void) { ticks++; return 0; }
static f32 mathSinf(f32 angle) { return sinf(angle); }
static f32 mathCosf(f32 angle) { return cosf(angle); }
static void cameraGetPrevPos2(GameObject* object, f32* x, f32* y, f32* z) {
    assert(object == &target);
    previousPositions++;
    *x = origin[0]; *y = origin[1]; *z = origin[2];
}
static void relativePosition(CameraObject* camera, f32* x, f32* y, f32* z,
                             f32* distance, f32 height, int flags) {
    *x = 100.0f; *y = 50.0f; *z = 0.0f; *distance = 100.0f;
}
typedef struct CameraInterface {
    void (*getRelativePosition)(CameraObject*, f32*, f32*, f32*, f32*, f32, int);
} CameraInterface;
static CameraInterface interface = {relativePosition};
static CameraInterface* interfacePointer = &interface;
static CameraInterface** gCameraInterface = &interfacePointer;
static int camcontrol_traceMove(f32* from, f32* to, f32* out, TrackHitResults* work,
                               char mode, u8 trace, u8 bbox, f32 radius) {
    assert(!out && mode == 7 && !trace && !bbox && radius == 3.9f);
    assert(to[1] == 50.0f);
    for (int i = 0; i < 3; i++) assert(isfinite(from[i]) && isfinite(to[i]));
    memset(work, 0, sizeof(*work));
    work->objects[0] = &target;
    work->hitCount = 1;
    work->hitMask = 1;
    if (from[1] == origin[1]) {
        CameraObject* candidate = (CameraObject*)((u8*)to -
            offsetof(CameraObject, worldPosition));
        assert(candidate->focusObj == &target.anim);
        assert(candidate->focusObject == &target);
        assert((uintptr_t)candidate->focusObj > UINT32_MAX);
        assert(candidate->anim.worldPosX == to[0] && candidate->anim.worldPosY == to[1] &&
               candidate->anim.worldPosZ == to[2]);
        for (int i = 0; i < 3; i++) assert(from[i] == origin[i]);
        assert(probes < answerCount);
        return answers[probes++];
    }
    assert(from[1] == 50.0f);
    segments++;
    return !(rejectPositiveSegment && segments == 1);
}
"""
CASES = r"""
static void run(const int* script, int count, int expectedSegments, int expectedResult,
                f32 initialOffset, f32 expectedOffset, int classId, int rejectSegment) {
    CameraObject camera = {0};
    memset(&state, 0, sizeof(state));
    memset(&target, 0, sizeof(target));
    target.anim.classId = classId;
    target.anim.worldPosX = 10.0f;
    target.anim.worldPosZ = 30.0f;
    camera.focusObject = &target;
    camera.anim.worldPosX = 110.0f;
    camera.anim.worldPosY = 50.0f;
    camera.anim.worldPosZ = 30.0f;
    state.targetHeight = 10.0f;
    state.avoidanceYawOffset = initialOffset;
    origin[0] = classId == 1 ? 1.0f : 10.0f;
    origin[1] = classId == 1 ? 2.0f : 10.0f;
    origin[2] = classId == 1 ? 3.0f : 30.0f;
    memcpy(answers, script, count * sizeof(*script));
    answerCount = count;
    probes = segments = ticks = previousPositions = 0;
    rejectPositiveSegment = rejectSegment;
    assert(CameraModeNormal_chooseWallAvoidanceDirection(&camera, NULL, NULL, 0x8000) == expectedResult);
    assert(probes == count && segments == expectedSegments && ticks == 1);
    assert(previousPositions == (classId == 1));
    assert(state.avoidanceYawOffset == expectedOffset);
}
int main(void) {
    const int blocked[12] = {0};
    const int bothClear[] = {1, 1};
    const int negativeFirst[] = {0, 1, 0, 0, 1};
    const int lastPositive[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0};
    assert(sizeof(void*) == 8);
    for (int classId = 1; classId <= 2; classId++) {
        run(blocked, 12, 0, 0, 7.0f, 7.0f, classId, 0);
        run(bothClear, 2, 2, 1, 0.0f, 10.0f, classId, 0);
        run(negativeFirst, 5, 5, 1, 0.0f, -10.0f, classId, 0);
        run(bothClear, 2, 2, 1, 0.0f, -10.0f, classId, 1);
        run(lastPositive, 12, 6, 1, 0.0f, 10.0f, classId, 0);
        run(bothClear, 2, 2, 1, 995.0f, 1000.0f, classId, 0);
        run(negativeFirst, 5, 5, 1, -995.0f, -1000.0f, classId, 0);
    }
    return 0;
}
"""


def harness():
    source = (ROOT / "src/dlls/engine/66/66.c").read_text()
    name = "CameraModeNormal_chooseWallAvoidanceDirection"
    start, end = find_function_body(source, name)
    declaration = source.rfind("int " + name, 0, start)
    return "\n".join([records(), SERVICES, source[declaration:end + 1], CASES])


class CameraWallSearchTests(unittest.TestCase):
    def test_native_camera_and_paths(self):
        with tempfile.TemporaryDirectory(prefix="camera-wall-search-") as directory:
            source = Path(directory) / "camera.c"
            source.write_text(harness())
            for optimization in ("-O0", "-O2"):
                with self.subTest(optimization=optimization):
                    executable = Path(directory) / "camera"
                    subprocess.run([
                        "clang", "-std=c11", optimization, "-Wall", "-Wextra", "-Werror",
                        "-Wno-unused-parameter", "-fsanitize=address,undefined", str(source),
                        "-o", str(executable), "-lm",
                    ], check=True, timeout=30)
                    subprocess.run([str(executable)], check=True, timeout=30)


if __name__ == "__main__":
    unittest.main()
