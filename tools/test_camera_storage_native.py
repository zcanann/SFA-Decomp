#!/usr/bin/env python3
"""Exercise recovered camera storage with independent globals and 64-bit records."""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PRELUDE = r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef int8_t s8;
typedef uint8_t u8;
typedef int16_t s16;
typedef uint16_t u16;
typedef int32_t s32;
typedef uint32_t u32;
typedef float f32;
typedef struct { f32 x, y, z; } Vec3f;
typedef f32 (*MtxPtr)[4];
#define STATIC_ASSERT(...)
'''
ADAPTER = r'''
/* Named engine fields remain usable at deliberately different native offsets. */
struct GameObject {
    void* hostPrefix;
    struct {
        s16 rotX, rotY, rotZ, pad;
        f32 rootMotionScale, localPosX, localPosY, localPosZ;
        struct GameObject* parent;
        s8 transformMatrixIndex;
    } anim;
    u32 objectFlags;
};
f32 playerMapOffsetX, playerMapOffsetZ;
f32 gCameraLightPerspectiveMatrix[3][4];
f32 gCameraLightPerspectiveFlipYMatrix[3][4];
f32 gCameraLightPerspectiveScaledMatrix[3][4];
'''
SERVICES = r'''
static int cases, mode, paused, sets, rotates, multiplies, transposes, lightCalls, projectionCalls;
static int depth, slot;
static GameObject objects[4];
static MatrixTransform expectedView, expectedInverse;
static void equalTransform(const MatrixTransform* a, const MatrixTransform* b) {
    assert(a->x == b->x && a->y == b->y && a->z == b->z && a->scale == b->scale);
    assert(a->rotX == b->rotX && a->rotY == b->rotY && a->rotZ == b->rotZ);
}
static void encode(f32* out, const MatrixTransform* t) {
    for (int i = 0; i < 16; i++) out[i] = 100+i;
    out[0] = t->x; out[1] = t->y; out[2] = t->z; out[3] = t->scale;
    out[4] = t->rotX; out[5] = t->rotY; out[6] = t->rotZ;
}
static MatrixTransform objectTransform(int index, int inverse) {
    GameObject* obj = &objects[index];
    MatrixTransform t = {0};
    f32 scale = 2+index;
    t.scale = obj->objectFlags & 8 ? (inverse ? 1/scale : scale) : 1;
    int sign = inverse ? -1 : 1;
    t.x = sign*(10+index); t.y = sign*(20+index); t.z = sign*(30+index);
    t.rotX = sign*(40+index); t.rotY = sign*(50+index); t.rotZ = sign*(60+index);
    return t;
}
static void setMatrixFromObjectPos(f32* out, const MatrixTransform* t) {
    if (mode == 1) {
        assert(out == gCameraWorldMatrix); equalTransform(t,&expectedInverse);
    } else {
        assert(mode == 2 && sets < depth);
        assert(out == (sets ? gObjectTransformScratchMatrix : gObjYawTransformMatrices[slot]));
        MatrixTransform expected = objectTransform(sets,0); equalTransform(t,&expected);
    }
    sets++; encode(out,t);
}
static void mtxRotateByVec3s(f32* out, const void* transform) {
    const MatrixTransform* t = transform;
    if (mode == 1) equalTransform(t,&expectedView);
    else {
        assert(mode == 2 && rotates < depth && out == gObjInverseYawTransformMatrices[slot]);
        MatrixTransform expected = objectTransform(depth-rotates-1,1); equalTransform(t,&expected);
    }
    rotates++; encode(out,t);
}
static void mtx44_multSafe(f32* a, f32* b, f32* out) {
    assert(mode == 2 && a == gObjYawTransformMatrices[slot]);
    assert(b == gObjectTransformScratchMatrix && out == a); multiplies++;
    for (int i = 0; i < 16; i++) out[i] += b[i];
}
static void mtx44Transpose(f32* in, f32* out) {
    assert(mode == 1 && out == (transposes ? gCameraInverseViewMatrix : gCameraViewMatrix));
    if (transposes) assert(in == gCameraWorldMatrix);
    for (int row = 0; row < 4; row++) for (int col = 0; col < 4; col++) out[4*row+col] = in[4*col+row];
    transposes++;
}
static void PSMTXCopy(MtxPtr in, MtxPtr out) { memcpy(out,in,12*sizeof(f32)); }
static int pauseMenuGetState(void) { return paused; }
static void C_MTXOrtho(f32 out[4][4],f32 top,f32 bottom,f32 left,f32 right,f32 near,f32 far) {
    (void)out; (void)top; (void)bottom; (void)left; (void)right; (void)near; (void)far; assert(0);
}
static void C_MTXPerspective(f32 out[4][4],f32 fov,f32 aspect,f32 near,f32 far) {
    assert(out == gCameraProjectionMatrix && fov == 60 && aspect == gCameraAspectRatio);
    assert(near == gCameraNearPlane && far == 10000);
    for (int i = 0; i < 4; i++) for (int j = 0; j < 4; j++) out[i][j] = 10*i+j;
}
static void C_MTXLightPerspective(MtxPtr out,f32 fov,f32 aspect,f32 x,f32 y,f32 tx,f32 ty) {
    assert(fov == 60 && aspect == gCameraAspectRatio && tx == .5f && ty == .5f);
    assert(out == (lightCalls == 0 ? gCameraLightPerspectiveScaledMatrix :
                   lightCalls == 1 ? gCameraLightPerspectiveMatrix : gCameraLightPerspectiveFlipYMatrix));
    assert(x == (lightCalls == 0 ? .4f : .5f));
    assert(y == (lightCalls == 0 ? .4f : lightCalls == 1 ? .5f : -.5f)); lightCalls++;
}
static void GXSetProjection(f32 out[4][4],int kind) {
    assert(out == gCameraProjectionMatrix && kind == 0); projectionCalls++;
}
static void mtx44Perspective(f32* out,u16* norm,f32 fov,f32 aspect,f32 near,f32 far,f32 scale) {
    assert(out == gCameraInitialPerspectiveMatrix && norm == &gCameraPerspectiveNorm);
    assert(fov == 60 && aspect == gCameraAspectRatio && near == gCameraNearPlane && far == 10000 && scale == 1);
    for (int i = 0; i < 16; i++) out[i] = 200+i;
    *norm = 123;
}
static void copyMatrix44(f32* in,f32* out) {
    assert(in == gCameraInitialPerspectiveMatrix && out == gCameraInitialPerspectiveCopy);
    memcpy(out,in,16*sizeof(f32));
}
'''
CHECKS = r'''
static void initCheck(void) {
    memset(gCameras,0x5a,sizeof(gCameras));
    Camera_InitState();
    for (int i = 0; i < CAMERA_COUNT; i++) {
        Camera* c = &gCameras[i];
        assert(c->x == 200 && c->y == 200 && c->z == 200 && c->fovY == 60);
        assert(c->yaw == 32760 && !c->pitch && !c->roll && !c->parentObject && !c->shakePitchOffset);
        assert(!c->velocity.x && !c->velocity.y && !c->velocity.z && !c->shakeOffsetY);
        assert(c->flags == 0x5a5a && c->shakeMode == 0x5a && c->pad1C[0] == 0x5a);
    }
    assert(lightCalls == 3 && projectionCalls == 1 && gCameraPerspectiveNorm == 123);
    assert(!memcmp(gCameraInitialPerspectiveMatrix,gCameraInitialPerspectiveCopy,16*sizeof(f32)));
    gCameraFarPlane = 300; Camera_ResetFarPlane();
    assert(gCameraFarPlane == 300 && gCameraFarPlaneTransitionStart == 300);
    assert(gCameraFarPlaneTransitionTarget == 10000 && gCameraFarPlaneTransitionFrames == 60);
    assert(gCameraFarPlaneTransitionFramesLeft == 60); cases++;
}
static void viewChecks(void) {
    mode = 1; playerMapOffsetX = 13; playerMapOffsetZ = -7;
    for (int i = 0; i < CAMERA_COUNT; i++) for (int state = 0; state < 4; state++) {
        Camera* c = &gCameras[i]; gCameraCurrentViewIndex = i;
        c->x = 40+i; c->y = 20+i; c->z = 30-i; c->yaw = 100+i; c->pitch = -20; c->roll = 35;
        c->shakeOffsetY = 3; paused = state&1; gCameraShakeEnabled = state>>1;
        expectedInverse = (MatrixTransform){(s16)-(c->yaw+32768),20,-35,0,1,c->x-13,c->y,c->z+7};
        if (!paused && gCameraShakeEnabled) expectedInverse.y += 3;
        expectedView = (MatrixTransform){(s16)(c->yaw+32768),-20,35,0,1,-expectedInverse.x,-expectedInverse.y,-expectedInverse.z};
        sets = rotates = transposes = 0; Camera_UpdateViewMatrices();
        assert(sets == 1 && rotates == 1 && transposes == 2);
        f32 expected[16]; encode(expected,&expectedView);
        for (int row = 0; row < 4; row++) for (int col = 0; col < 4; col++) {
            int j = 4*row+col; assert(gCameraViewMatrix[j] == expected[4*col+row]);
            if (j < 12) assert(gCameraViewRotationMatrix[j] == (col == 3 ? 0 : gCameraViewMatrix[j]));
        }
        for (int j = 0; j < 12; j++) assert(gCameraInverseViewRotationMatrix[j] == (j%4 == 3 ? 0 : gCameraInverseViewMatrix[j]));
        cases++;
    }
}
static void parentChecks(void) {
    mode = 2;
    for (slot = 0; slot < OBJECT_TRANSFORM_MATRIX_COUNT; slot++) for (depth = 0; depth <= 4; depth++) {
        for (int i = 0; i < 4; i++) {
            GameObject* obj = &objects[i]; obj->objectFlags = i&1 ? 8 : 0;
            obj->anim.rotX = 40+i; obj->anim.rotY = 50+i; obj->anim.rotZ = 60+i;
            obj->anim.localPosX = 10+i; obj->anim.localPosY = 20+i; obj->anim.localPosZ = 30+i;
            obj->anim.rootMotionScale = 2+i; obj->anim.parent = i+1 < depth ? &objects[i+1] : NULL;
        }
        sets = rotates = multiplies = 0;
        Obj_BuildTransformMatricesForYaw(depth ? objects : NULL,slot);
        assert(sets == depth && rotates == depth && multiplies == (depth ? depth-1 : 0));
        for (int i = 0; i < 4; i++) assert(objects[i].anim.rootMotionScale == 2+i);
        cases++;
    }
}
int main(void) {
    assert(sizeof(void*) == 8 && sizeof(Camera) > 0x60 && (uintptr_t)gCameras > UINT32_MAX);
    initCheck(); viewChecks(); parentChecks();
    printf("%d camera storage scenarios passed with native pointers and independent globals\n",cases);
}
'''


def function(source, name):
    match = re.search(r'^(?:static )?(?:inline )?[\w* ]+\b' + name + r'\([^;]*?\)\s*\{', source, re.M)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[match.start():end]


def harness():
    source = (ROOT / 'src/main/camera.c').read_text()
    header = (ROOT / 'include/main/camera.h').read_text()
    header = re.sub(r'^#include[^\n]*\n', '', header, flags=re.M)
    transform = re.search(r'typedef struct MatrixTransform \{.*?\} MatrixTransform;',
                          (ROOT / 'include/main/vecmath.h').read_text(), re.S)[0]
    globals_ = source[:source.index('static void Obj_BuildTransformMatricesForYaw')]
    globals_ = re.sub(r'^#include[^\n]*\n', '', globals_, flags=re.M)
    names = ['Camera_ResetView', 'Camera_SetFarPlane', 'Camera_ResetFarPlane', 'Camera_InitState',
             'Obj_BuildTransformMatricesForYaw', 'Camera_UpdateViewMatrices']
    return '\n'.join([PRELUDE, transform, header, ADAPTER, globals_, SERVICES,
                      *(function(source, name) for name in names), CHECKS])


class CameraStorageNativeTest(unittest.TestCase):
    def test_recovered_storage(self):
        compiler = shutil.which('clang') or shutil.which('cc')
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory(prefix='camera-storage-') as directory:
            path = Path(directory)
            source = path / 'camera.c'
            source.write_text(harness())
            for optimization in ['-O0', '-O2']:
                with self.subTest(optimization=optimization):
                    exe = path / 'camera'
                    subprocess.run([compiler, '-std=c11', optimization, '-g', '-Wall', '-Wextra', '-Werror',
                                    '-fsanitize=address,undefined', '-fno-common', '-fno-omit-frame-pointer',
                                    str(source), '-o', str(exe)], check=True, timeout=30)
                    subprocess.run([str(exe)], check=True, timeout=30)


if __name__ == '__main__':
    unittest.main()
