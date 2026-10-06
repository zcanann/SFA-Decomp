#!/usr/bin/env python3
"""Exercise the recovered staff-camera return, storage and mode-exit contracts."""

from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from brute_match import find_function_body
from test_camera_update_storage import records

ROOT = Path(__file__).resolve().parents[1]
SERVICES = r"""
static CameraModeStaffAnimState state;
static CameraModeStaffAnimState* gCameraModeStaffAnimState = &state;
static GameObject target, oldFrame, newFrame;
static CameraObject camera;
static f32 timeDelta = 2.0f, expectedT, curveSpeed, expectedSpeed;
static int pathFinished, followCalls, boundsCalls, slideCalls, pitchCalls, actionCalls;
static int modeCalls, advanceCalls, resetCalls, blockedCalls, transformCalls, collisionKind;
static void Obj_TransformLocalPointToWorld(f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz, GameObject* parent) {
    *ox = x + (parent ? parent->anim.worldPosX : 0);
    *oy = y + (parent ? parent->anim.worldPosY : 0);
    *oz = z + (parent ? parent->anim.worldPosZ : 0);
    transformCalls++;
}
static void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz, GameObject* parent) {
    *ox = x - (parent ? parent->anim.worldPosX : 0);
    *oy = y - (parent ? parent->anim.worldPosY : 0);
    *oz = z - (parent ? parent->anim.worldPosZ : 0);
    transformCalls++;
}
static void follow(void* record, ObjAnimComponent* focus) {
    CameraObject* work = record;
    assert(work != &camera && work->focusObject == &target && focus == &target.anim);
    assert(work->localFrameObj == camera.localFrameObj);
    assert(work->prevLocalX == work->localX && work->prevLocalY == work->localY &&
           work->prevLocalZ == work->localZ);
    assert(work->prevWorldX == work->localX + (work->localFrameObj ? work->localFrameObj->anim.worldPosX : 0));
    assert(work->collisionResults.hitCount == 0 && work->frameFlags == 0);
    work->localX += 1000.0f;
    work->localZ += 3000.0f;
    followCalls++;
}
static void bounds(void* record, int flags, int mode, f32* floor, f32* ceiling) {
    CameraObject* work = record;
    assert(flags == 1 && mode == 3 && floor == &state.floorHeight && ceiling == &state.ceilingHeight);
    /* Exercise the complete native-width collision record inside both cameras. */
    memset(&work->collisionResults, 0, sizeof(work->collisionResults));
    work->collisionResults.objects[TRACK_HIT_MAX_POINTS - 1] = &target;
    assert(work->focusObject == &target);
    if (work == &camera) {
        work->collisionResults.hitCount = collisionKind == 1;
        work->cameraCollisionActive = collisionKind == 2;
    }
    *floor = -100.0f;
    *ceiling = 100.0f;
    boundsCalls++;
}
static void slide(void* record, GameObject* focus, f32 floor, f32 ceiling) {
    assert(record == &camera && focus == &target && floor == -100000.0f && ceiling == 100000.0f);
    slideCalls++;
}
static void pitch(void* record, double targetY, double distance) {
    assert(record == &camera && targetY == target.anim.worldPosY && distance == 5.0);
    pitchCalls++;
}
static CamcontrolDefaultHandlerVTable vtable = {
    .follow = follow, .updatePitch = pitch, .updateSlide = slide, .updateVerticalBounds = bounds,
};
static CamcontrolDefaultHandler handler = {&vtable};
static CamcontrolDefaultHandlerEntry entry = {.handler = &handler};
static void* getDefaultHandler(void) { return &entry; }
static void setMode(int mode, int arg1, int arg2, int size, void* params, int frames, int priority) {
    assert(mode == CAMCONTROL_ACTION_DEFAULT && arg1 == 0 && arg2 == 1 && size == 0);
    assert(!params && frames == 0 && priority == 0xff);
    modeCalls++;
}
static void relative(void* record, f32* x, f32* y, f32* z, f32* distance, f32 height, int local) {
    assert(record == &camera && height == 0 && local == 0);
    *x = 3; *y = 0; *z = 4; *distance = 5;
}
static CameraInterface interface = {.getDefaultHandlerEntry = getDefaultHandler, .setMode = setMode,
                                    .getRelativePosition = relative};
static CameraInterface* interfacePointer = &interface;
static CameraInterface** gCameraInterface = &interfacePointer;
static f32 Curve_EvalHermite(f32* values, f32 t, f32* tangent) {
    assert(values == state.pathSpeedCurve && t == expectedT && !tangent);
    return curveSpeed;
}
static int Curve_AdvanceAlongPath(Curve* curve, f32 speed) {
    assert(curve == &state.pathCurve && speed == expectedSpeed);
    curve->sample[0] = 444.0f;
    curve->sample[1] = 555.0f;
    curve->sample[2] = 666.0f;
    advanceCalls++;
    return pathFinished;
}
static u8 camcontrol_getTargetPosition(void* record, ObjAnimComponent* focus, f32* world, s16* pitchOut) {
    assert(record == &camera && focus == &target.anim && world == camera.worldPosition);
    assert(pitchOut == &camera.anim.rotY);
    world[0] = 71; world[1] = 72; world[2] = 73;
    resetCalls++;
    return 1;
}
static void camcontrol_onTargetTraceBlocked(int blocked) { assert(blocked == 1); blockedCalls++; }
static u32 getAngle(f32 x, f32 z) { assert(x == 3 && z == 4); return 0; }
static void CameraModeStaffAnim_updateTargetAction(CameraObject* record, GameObject* focus) {
    assert(record == &camera && focus == &target);
    actionCalls++;
}
"""
CASES = r"""
static void setup(void) {
    memset(&state, 0, sizeof(state));
    memset(&target, 0, sizeof(target));
    memset(&camera, 0, sizeof(camera));
    state.pathCurve.count = 6;
    state.pathCurve.pathLength = 10;
    state.pathCurve.pathDistance = 5;
    for (int i = 0; i < 6; i++) {
        state.pointsX[i] = i;
        state.pointsY[i] = i * 10;
        state.pointsZ[i] = -i;
    }
    camera.focusObject = &target;
    camera.anim.localPosY = 25;
    target.anim.worldPosY = 15;
    expectedT = 0.5f;
    curveSpeed = expectedSpeed = 0.75f;
    followCalls = boundsCalls = slideCalls = pitchCalls = actionCalls = modeCalls = 0;
    advanceCalls = resetCalls = blockedCalls = transformCalls = collisionKind = pathFinished = 0;
}
static void sampleCase(f32 distance, f32 length, f32 clampedT, f32 speed, int finished) {
    f32 x, y = 25, z;
    setup();
    state.pathCurve.pathDistance = distance;
    state.pathCurve.pathLength = length;
    state.collisionTime = 17;
    expectedT = clampedT;
    curveSpeed = speed;
    expectedSpeed = speed < 0.2f ? 0.2f : speed;
    pathFinished = finished;
    assert(CameraModeStaffAnim_samplePath(&x, &y, &z, &target, &camera) == finished);
    assert(x == 444 && y == 25 && z == 666);
    assert(followCalls == 1 && boundsCalls == 1 && advanceCalls == 1 && transformCalls == 2);
    assert(state.collisionTime == 17);
    for (int i = 0; i < 6; i++) {
        assert(state.pointsX[i] == (i < 3 ? i : 1004));
        assert(state.pointsZ[i] == (i < 3 ? -i : 2996));
        assert(state.pointsY[i] == i * 10);
    }
}
static void updateCase(int finished, int collision, int priorCollision, int changeFrame) {
    setup();
    pathFinished = finished;
    collisionKind = collision;
    state.collisionTime = priorCollision ? 7.0f : 0;
    if (changeFrame) {
        oldFrame.anim.worldPosX = -10; oldFrame.anim.worldPosY = 0; oldFrame.anim.worldPosZ = 10;
        newFrame.anim.worldPosX = 1; newFrame.anim.worldPosY = 2; newFrame.anim.worldPosZ = 3;
        state.localFrame = &oldFrame;
        camera.localFrameObj = &newFrame;
    }
    CameraModeStaffAnim_update(&camera);
    assert(followCalls == 1 && boundsCalls == 2 && advanceCalls == 1);
    assert(slideCalls == 1 && pitchCalls == 1 && actionCalls == 1);
    assert(modeCalls == (finished || collision || priorCollision));
    assert(state.collisionTime == (priorCollision ? 7.0f : 0) + (collision ? timeDelta : 0));
    assert(resetCalls == (collision || priorCollision) && blockedCalls == resetCalls);
    if (resetCalls) {
        assert(camera.prevWorldX == 71 && camera.prevWorldY == 72 && camera.prevWorldZ == 73);
    } else {
        assert(camera.anim.localPosX == 444 && camera.anim.localPosY == 25 && camera.anim.localPosZ == 666);
    }
    assert(state.localFrame == camera.localFrameObj);
    assert(transformCalls == (changeFrame ? 16 : 4));
    if (changeFrame) {
        assert(state.pointsX[0] == -11 && state.pointsY[0] == -2 && state.pointsZ[0] == 7);
    }
}
int main(void) {
    assert(sizeof(void*) == 8 && (uintptr_t)&entry > UINT32_MAX);
    sampleCase(-10, 10, 0, 0.1f, 0);
    sampleCase(0, 0, 0, -1.0f, 1);
    sampleCase(5, 10, 0.5f, 0.75f, 0);
    sampleCase(20, 10, 1, 2.0f, 1);
    for (int finished = 0; finished <= 1; finished++) {
        for (int collision = 0; collision <= 2; collision++) {
            updateCase(finished, collision, 0, 0);
        }
    }
    updateCase(0, 0, 1, 0);
    updateCase(0, 0, 0, 1);
    setup();
    state.pathNotNeeded = 1;
    CameraModeStaffAnim_update(&camera);
    assert(modeCalls == 1 && !followCalls && !advanceCalls && !actionCalls && !transformCalls);
    return 0;
}
"""


def harness():
    parts = [records()]
    for path in ("include/main/curve_eval.h", "include/main/curve_types.h",
                 "include/main/dll/dll_0043_cameramodestaffanim.h",
                 "include/main/dll/CAM/dll_0001_camcontrol.h", "include/main/camera_interface.h"):
        header = (ROOT / path).read_text()
        if path.endswith("curve_eval.h"):
            parts.append("\n".join(re.findall(r"typedef[^;]+;", header)))
        elif path.endswith("curve_types.h"):
            parts.append(re.search(r"typedef struct Curve\s*\{.*?\} Curve;", header, re.S)[0])
        elif path.endswith("dll_0043_cameramodestaffanim.h"):
            parts.append(re.search(r"enum CameraModeStaffAnimPathCapacity \{.*?\};", header, re.S)[0])
            parts.append(re.search(r"typedef struct CameraModeStaffAnimState \{.*?\} CameraModeStaffAnimState;",
                                   header, re.S)[0])
        elif path.endswith("dll_0001_camcontrol.h"):
            start = header.index("typedef void (*CamcontrolHandlerReservedFn)")
            end = header.index("STATIC_ASSERT(sizeof(CamcontrolHandlerVTable)")
            parts.append(header[start:end])
            parts.append(re.search(r"enum CamcontrolActionId \{.*?\};", header, re.S)[0])
        else:
            parts.append(header[header.index("typedef int (*CameraGetModeFn)"):header.index("STATIC_ASSERT(")])
    parts.append(SERVICES)
    source = (ROOT / "src/dlls/engine/67/67.c").read_text()
    for name, result in (("CameraModeStaffAnim_samplePath", "int"), ("CameraModeStaffAnim_update", "void")):
        start, end = find_function_body(source, name)
        declaration = source.rfind(result + " " + name, 0, start)
        parts.append(source[declaration:end + 1])
    return "\n".join(parts + [CASES])


class StaffCameraTests(unittest.TestCase):
    def test_native_path_and_update(self):
        with tempfile.TemporaryDirectory(prefix="staff-camera-") as directory:
            source = Path(directory) / "camera.c"
            source.write_text(harness())
            for optimization in ("-O0", "-O2"):
                with self.subTest(optimization=optimization):
                    executable = Path(directory) / "camera"
                    subprocess.run([
                        "clang", "-std=c11", optimization, "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=address,undefined", str(source), "-o", str(executable),
                    ], check=True, timeout=30)
                    subprocess.run([str(executable)], check=True, timeout=30)


if __name__ == "__main__":
    unittest.main()
