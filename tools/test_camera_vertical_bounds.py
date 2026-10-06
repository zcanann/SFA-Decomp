#!/usr/bin/env python3
"""Check native pointer flow and retail floor/ceiling selection in the camera."""

from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from brute_match import find_function_body
from test_camera_update_storage import records

ROOT = Path(__file__).resolve().parents[1]
SERVICES = r"""
static CameraObject camera;
static GameObject focus, parent;
static TrackGroundHit candidates[12];
static TrackGroundHit* hits[12];
static int hitCount, lineCalls, boundsCalls, broadphaseCalls, intersectCalls, heightCalls, transformCalls;
static int activeFlags;
static int trackGetLineIntersect(f32* from, f32* to, f32 radius, int count, void* a, void* b,
                                 int flags, u32 mask, int layer, int unused) {
    assert(from == &camera.prevWorldX && to == camera.worldPosition);
    assert(radius == 4 && count == 1 && !a && !b && flags == 0x10 && mask == UINT32_MAX);
    assert(layer == 0xff && unused == 0);
    to[0] = 20; to[2] = 40;
    lineCalls++;
    return 0x101; /* The camera keeps the low byte. */
}
static void hitDetect_calcSweptSphereBounds(TrackQueryBounds* bounds, f32* from, f32* to,
                                           f32* radii, int count) {
    assert(from == &camera.prevWorldX && to != camera.worldPosition && count == 1);
    assert(to[0] == 20 && to[1] == 100 && to[2] == 40);
    assert(radii == camera.collisionResults.radii && radii[0] == 4);
    *bounds = (TrackQueryBounds){1, 2, 3, 4, 5, 6};
    boundsCalls++;
}
static void trackIntersectBroadphase(GameObject* object, TrackQueryBounds* bounds, u32 mask, int flags) {
    assert(object == &focus && (uintptr_t)object > UINT32_MAX);
    assert(bounds->minX == 1 && bounds->maxZ == 6 && mask == 0x240 && flags == 1);
    broadphaseCalls++;
}
static void trackGetIntersect(GameObject* object, f32* from, f32* to, int count,
                              TrackHitResults* result, int flags) {
    assert(object == &focus && from == &camera.prevWorldX && count == 1 && flags == 0);
    assert(result == &camera.collisionResults && result->surfaceTypes[0] == -1);
    assert(result->queryTypes[0] == 8 && result->radii[0] == 4);
    assert(to[0] == 20 && to[1] == 100 && to[2] == 40);
    memset(result, 0, sizeof(*result));
    for (int i = 0; i < TRACK_HIT_MAX_POINTS; i++) result->objects[i] = &focus;
    result->hitCount = 1;
    result->hitMask = 0x10;
    to[0] = 50; to[2] = 60;
    intersectCalls++;
}
static int trackGetHeight(GameObject* object, f32 x, f32 y, f32 z, TrackGroundHit*** out, int mode, int mask) {
    assert(object == &focus && (uintptr_t)object > UINT32_MAX);
    assert(x == ((activeFlags & 1) ? 50 : 10) && y == 100 && z == ((activeFlags & 1) ? 60 : 30));
    assert(mode == 1 && mask == 0x40);
    *out = hits;
    heightCalls++;
    return hitCount;
}
static void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz, GameObject* frame) {
    assert(frame == &parent);
    assert(ox == &camera.localX && oy == &camera.localY && oz == &camera.localZ);
    *ox = x - 1; *oy = y - 2; *oz = z - 3;
    transformCalls++;
}
"""
CASES = r"""
static void setup(int flags) {
    memset(&camera, 0, sizeof(camera));
    memset(candidates, 0, sizeof(candidates));
    hitCount = lineCalls = boundsCalls = broadphaseCalls = intersectCalls = heightCalls = transformCalls = 0;
    activeFlags = flags;
    camera.focusObject = &focus;
    camera.localFrameObj = &parent;
    camera.worldX = 10; camera.worldY = 100; camera.worldZ = 30;
    camera.prevWorldX = 1; camera.prevWorldY = 2; camera.prevWorldZ = 3;
    camera.floorNormalY = 2;
    camera.ceilingNormalY = -2;
    camera.cameraCollisionActive = 9;
}
static void addHit(f32 height, f32 normalY) {
    assert(hitCount < 12);
    candidates[hitCount] = (TrackGroundHit){.height = height, .normalX = 7, .normalY = normalY,
                                           .normalZ = 8, .object = &focus};
    hits[hitCount] = &candidates[hitCount];
    hitCount++;
}
static void check(f32 expectedFloor, f32 expectedCeiling, f32 floorNormal, f32 ceilingNormal) {
    f32 floor = -7, ceiling = 7;
    CameraModeNormal_updateVerticalBounds(&camera, activeFlags, 8, &floor, &ceiling);
    assert(floor == expectedFloor && ceiling == expectedCeiling);
    assert(camera.floorNormalY == floorNormal && camera.ceilingNormalY == ceilingNormal);
    assert(lineCalls == !!(activeFlags & 1) && boundsCalls == lineCalls);
    assert(broadphaseCalls == lineCalls && intersectCalls == lineCalls);
    assert(heightCalls == !!(activeFlags & 2) && transformCalls == 1);
    assert(camera.localX == ((activeFlags & 1) ? 49 : 9) && camera.localY == 98);
    assert(camera.localZ == ((activeFlags & 1) ? 57 : 27));
    assert(camera.cameraCollisionActive == ((activeFlags & 1) ? 1 : 9));
    assert(camera.focusObject == &focus);
    if (activeFlags & 1) {
        assert(camera.collisionResults.hitMask == 0x10 && camera.collisionResults.hitCount == 1);
        assert(camera.collisionResults.objects[TRACK_HIT_MAX_POINTS - 1] == &focus);
    }
}
int main(void) {
    assert(sizeof(void*) == 8);
    for (int flags = 0; flags <= 3; flags++) {
        setup(flags);
        check((flags & 2) ? -100000 : -7, (flags & 2) ? 100000 : 7, 2, -2);
    }
    for (int flags = 2; flags <= 3; flags++) {
        setup(flags);
        addHit(150, -1); addHit(120, -0.5f); addHit(104, -0.25f);
        addHit(50, 1); addHit(80, 0.5f); addHit(96, 0.25f);
        addHit(100, 0); /* A vertical face is neither floor nor ceiling. */
        check(96, 104, 0.25f, -0.25f);

        setup(flags);
        addHit(90, -1); addHit(89, -1); addHit(110, 1); addHit(111, 1);
        check(-100000, 100000, 2, -2); /* Strict ten-unit tolerance. */

        setup(flags);
        addHit(91, -0.125f); addHit(109, 0.125f);
        check(109, 91, 0.125f, -0.125f); /* Retail permits the tolerance overlap. */

        setup(flags);
        addHit(97, -0.25f); addHit(103, -0.5f);
        addHit(103, 0.25f); addHit(97, 0.5f);
        check(103, 97, 0.25f, -0.25f); /* Equal-distance candidates keep the first hit. */
    }
    return 0;
}
"""


def harness():
    parts = [records()]
    header = (ROOT / "include/main/track_hit_results.h").read_text()
    for name in ("TrackGroundHit", "TrackQueryBounds"):
        parts.append(re.search(rf"typedef struct {name}\s*\{{.*?\}} {name};", header, re.S)[0])
    parts.append(SERVICES)
    source = (ROOT / "src/dlls/engine/66/66.c").read_text()
    start, end = find_function_body(source, "CameraModeNormal_updateVerticalBounds")
    declaration = source.rfind("void CameraModeNormal_updateVerticalBounds", 0, start)
    return "\n".join(parts + [source[declaration:end + 1], CASES])


class CameraVerticalBoundsTests(unittest.TestCase):
    def test_native_collision_and_height_bounds(self):
        with tempfile.TemporaryDirectory(prefix="camera-vertical-bounds-") as directory:
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
