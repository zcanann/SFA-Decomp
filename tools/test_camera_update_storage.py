#!/usr/bin/env python3
"""Exercise normal-camera trace locals using native-sized collision records."""

from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from brute_match import find_function_body

ROOT = Path(__file__).resolve().parents[1]
PRELUDE = r"""
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
typedef uint8_t u8;
typedef int8_t s8;
typedef uint16_t u16;
typedef int16_t s16;
typedef uint32_t u32;
typedef int32_t s32;
typedef float f32;
typedef struct GameObject GameObject;
/* Semantic object fixtures: only collision records and mode state use the
 * production definitions. This does not emulate the target object ABI. */
typedef struct ObjAnimComponent {
    union { struct { f32 worldPosX, worldPosY, worldPosZ; }; f32 worldPos[3]; };
    f32 localPosX, localPosY, localPosZ, velocityY;
    s16 rotX, rotY, rotZ, classId;
    GameObject* targetObj;
    GameObject* parent;
} ObjAnimComponent;
struct GameObject { ObjAnimComponent anim; };
"""
SERVICES = r"""
typedef struct CameraObject {
    ObjAnimComponent anim;
    TrackHitResults collisionResults;
    f32 boundHitZUpper, boundHitZLower, probePosX, probePosY, probePosZ;
    u8 cameraCollisionActive, unk13E;
} CameraObject;
static CameraModeNormalState state;
static CameraModeNormalState* gCameraModeNormalState = &state;
static f32 timeDelta = 2.0f, gCameraModeNormalScaledTimeDelta;
static f32 expectedOrigin[3];
static int traces, previousPositions, actions, angleCalls;
static void playerGetTimeScale(GameObject* target, f32* result) { *result = 0.5f; }
static int EmissionController_IsLingering(GameObject* target) { return 0; }
static void CameraModeNormal_updateSettings(CameraObject* camera) {}
static void CameraModeNormal_updateWallAvoidance(CameraObject* camera, GameObject* target) {}
static void CameraModeNormal_follow(CameraObject* camera, ObjAnimComponent* target) {}
static void CameraModeNormal_updateSlide(CameraObject* camera, GameObject* target, f32 upper, f32 lower) {}
static void CameraModeNormal_updateVerticalBounds(CameraObject* camera, int flags, int collision,
                                                  f32* upper, f32* lower) {}
static void Obj_TransformLocalPointToWorld(f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz, GameObject* parent) {
    *ox = x; *oy = y; *oz = z;
}
static void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz, GameObject* parent) {
    *ox = x; *oy = y; *oz = z;
}
static void cameraGetPrevPos2(GameObject* target, f32* x, f32* y, f32* z) {
    previousPositions++;
    *x = 101.0f; *y = 202.0f; *z = 303.0f;
}
static int camcontrol_traceMove(f32* from, f32* to, f32* out, TrackHitResults* work,
                               char mode, u8 trace, u8 bbox, f32 radius) {
    for (int i = 0; i < 3; i++) assert(from[i] == expectedOrigin[i]);
    assert(to == out && mode == 3 && trace == 1 && bbox == 1 && radius == 4.0f);
    /* Writing every field catches buffers sized for 32-bit object pointers. */
    memset(work, 0, sizeof(*work));
    for (int i = 0; i < TRACK_HIT_MAX_POINTS; i++) work->objects[i] = NULL;
    work->hitCount = 1;
    work->hitMask = 1;
    for (int i = 0; i < 3; i++) out[i] = to[i] + 10.0f * (i + 1);
    traces++;
    return 1;
}
static void relativePosition(CameraObject* camera, f32* x, f32* y, f32* z,
                             f32* distance, f32 height, int flags) {
    *x = 3.0f; *y = 20.0f; *z = 4.0f; *distance = 5.0f;
}
typedef struct CameraInterface {
    void (*getRelativePosition)(CameraObject*, f32*, f32*, f32*, f32*, f32, int);
} CameraInterface;
static CameraInterface interface = {relativePosition};
static CameraInterface* interfacePointer = &interface;
static CameraInterface** gCameraInterface = &interfacePointer;
static u32 getAngle(f32 y, f32 x) {
    if ((angleCalls++ & 1) == 0) assert(y == 3.0f && x == 4.0f);
    else assert(x == 5.0f);
    return 0;
}
static int interpolate(f32 value, f32 speed, f32 delta) { return 0; }
static void CameraModeNormal_updateTargetAction(CameraObject* camera, GameObject* target) { actions++; }
"""
CASES = r"""
static void run(int classId) {
    GameObject target = {0};
    CameraObject camera = {0};
    memset(&state, 0, sizeof(state));
    traces = previousPositions = actions = angleCalls = 0;
    target.anim.classId = classId;
    target.anim.worldPosX = 10.0f;
    target.anim.worldPosY = 20.0f;
    target.anim.worldPosZ = 30.0f;
    camera.anim.targetObj = &target;
    camera.anim.localPosX = 40.0f;
    camera.anim.localPosY = 60.0f;
    camera.anim.localPosZ = 80.0f;
    camera.cameraCollisionActive = 1;
    camera.collisionResults.hitMask = 0x10;
    camera.collisionResults.planes[0][1] = 0.5f;
    state.targetHeight = 5.0f;
    state.yawResponseFrames = 8;
    state.clampFlags.distanceClamped = 1;
    state.wallAvoidanceTimer = 10;
    state.collisionProbeTimer = 5;
    expectedOrigin[0] = classId == 1 ? 101.0f : 10.0f;
    expectedOrigin[1] = classId == 1 ? 202.0f : 25.0f;
    expectedOrigin[2] = classId == 1 ? 303.0f : 30.0f;
    CameraModeNormal_update(&camera);
    assert(traces == 2 && previousPositions == (classId == 1 ? 2 : 0));
    assert(actions == 1 && state.collisionHitMask == 0x10);
    assert(state.wallAvoidanceTimer == 0 && state.collisionProbeTimer == 0);
    assert(camera.probePosX == 60.0f && camera.probePosY == 100.0f && camera.probePosZ == 140.0f);
    assert(camera.anim.localPosX == 60.0f && camera.anim.localPosY == 100.0f && camera.anim.localPosZ == 140.0f);
    assert(gCameraModeNormalScaledTimeDelta == (classId == 1 ? 1.0f : 2.0f));

    /* The upward/downward plane tests consume collision data, not animation fields. */
    camera.collisionResults.planes[0][1] = -1.0f;
    CameraModeNormal_update(&camera);
    assert(traces == 2 && state.clampFlags.heightLocked == 1);
    assert(state.heightLockLimit == camera.anim.worldPosY);
    camera.anim.targetObj = NULL;
    CameraModeNormal_update(&camera);
    assert(actions == 2 && traces == 2);
}
int main(void) {
    assert(sizeof(void*) == 8 && sizeof(TrackHitResults) > 116);
    run(1);
    run(2);
    return 0;
}
"""


def harness():
    parts = [PRELUDE]
    for path, names in (
        ("include/main/track_hit_results.h", ("TrackHitResults",)),
        ("include/main/dll/dll_0042_cameramodenormal.h", (
            "CameraModeNormalWallAvoidanceFlags", "CameraModeNormalClampFlags", "CameraModeNormalState")),
    ):
        header = (ROOT / path).read_text()
        if "TrackHitResults" in names:
            parts.append(re.search(r"^#define TRACK_HIT_MAX_POINTS[^\n]*", header, re.M)[0])
        for name in names:
            parts.append(re.search(rf"typedef struct {name}\s*\{{.*?\}} {name};", header, re.S)[0])
    parts.append(SERVICES)
    source = (ROOT / "src/dlls/engine/66/66.c").read_text()
    start, end = find_function_body(source, "CameraModeNormal_update")
    declaration = source.rfind("void CameraModeNormal_update", 0, start)
    return "\n".join(parts + [source[declaration:end + 1], CASES])


class CameraUpdateStorageTests(unittest.TestCase):
    def test_native_trace_storage(self):
        with tempfile.TemporaryDirectory(prefix="camera-update-storage-") as directory:
            source = Path(directory) / "camera.c"
            source.write_text(harness())
            for optimization in ("-O0", "-O2"):
                with self.subTest(optimization=optimization):
                    executable = Path(directory) / "camera"
                    subprocess.run([
                        "clang", "-std=c11", optimization, "-Wall", "-Wextra", "-Werror",
                        "-Wno-unused-parameter", "-fsanitize=address,undefined", str(source),
                        "-o", str(executable),
                    ], check=True, timeout=30)
                    subprocess.run([str(executable)], check=True, timeout=30)


if __name__ == "__main__":
    unittest.main()
