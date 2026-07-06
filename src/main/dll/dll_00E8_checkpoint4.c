/*
 * DLL 0x00E8 - checkpoint4. TU range 0x801719E0-0x80171BAC.
 *
 * The TU's own object is the "checkpoint4" trigger volume: checkpoint4_init
 * builds an oriented plane (normal + signed distance via setMatrixFromObjectPos
 * + Matrix_TransformPoint) from the placement rotation/radius, seeds a set
 * of random headings, and stows the checkpoint index. checkpoint4_render emits a
 * plain model render. The rest of the callbacks are stubs.
 *
 * The TU also owns the .data descriptor cluster for the sideload / siderepel /
 * setuppoint / collectible / magicgem siblings (their callbacks live in their
 * own DLLs and are referenced here as externs).
 */
#include "main/dll/xyzanimator.h"
#include "main/dll/genprops.h"
#include "main/objprint.h"
#include "main/objlib.h"
#include "main/dll/fx_800944A0_shared.h"

extern const f32 lbl_803E3420;
extern f32 lbl_803E3424;
extern f32 lbl_803E3428;
extern const f32 lbl_803E342C;
extern f32 lbl_803E3430;

extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);

void checkpoint4_setScale(void)
{
}

int checkpoint4_getExtraSize(void) { return 0x40; }
int checkpoint4_getObjectTypeId(void) { return 0x10; }

void checkpoint4_free(void)
{
}

void checkpoint4_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E3420);
}

void checkpoint4_hitDetect(void)
{
}

void checkpoint4_update(void)
{
}

#pragma opt_common_subs off
void checkpoint4_init(Checkpoint4Object* checkpoint, Checkpoint4Placement* placement)
{
    f32 radius;
    u32 heading;
    int i;
    f32 yy;
    Checkpoint4State* state;
    Checkpoint4MatrixBuildTransform transform;
    f32 matrix[16];
    extern void Matrix_TransformPoint(f32* matrix, f32 x, f32 y, f32 z, f32* outX, f32* outY, f32* outZ); /* #57 */

    state = checkpoint->state;
    radius = (f32)(int)placement->radius;
    if ((f32)(int)placement->radius < *(f32*)&lbl_803E3424)
    {
        radius = lbl_803E3424;
    }
    radius = radius * lbl_803E3428;
    checkpoint->objAnim.rootMotionScale = radius;
    checkpoint->objAnim.rotX = (s16)((s16)placement->rotX << 8);
    transform.rotX = checkpoint->objAnim.rotX;
    transform.rotY = checkpoint->objAnim.rotY;
    transform.rotZ = checkpoint->objAnim.rotZ;
    transform.scale = lbl_803E3420;
    transform.x = lbl_803E342C;
    transform.y = lbl_803E342C;
    transform.z = lbl_803E342C;
    setMatrixFromObjectPos(matrix, &transform);
    Matrix_TransformPoint(matrix, lbl_803E342C, lbl_803E342C, lbl_803E3420,
                          &state->planeNormalX, &state->planeNormalY, &state->planeNormalZ);
    yy = checkpoint->objAnim.localPosY * state->planeNormalY;
    state->planeDistance =
        -(yy + checkpoint->objAnim.localPosX * state->planeNormalX +
            checkpoint->objAnim.localPosZ * state->planeNormalZ);
    state->triggerRadius = lbl_803E3430 * checkpoint->objAnim.rootMotionScale;
    i = 0;
    do
    {
        heading = randomGetRange(0, CHECKPOINT4_RANDOM_HEADING_MAX);
        state->randomHeadings[i] = heading;
        i++;
    }
    while (i < CHECKPOINT4_RANDOM_HEADING_COUNT);
    checkpoint->checkpointIndex = placement->checkpointIndex;
    checkpoint->objectFlags |= CHECKPOINT4_OBJECT_FLAGS_ENABLED;
}
#pragma opt_common_subs reset

void checkpoint4_release(void)
{
}

void checkpoint4_initialise(void)
{
}

extern void magicgem_getExtraSize();
extern void magicgem_free();
extern void magicgem_render();
extern void magicgem_update();
extern void magicgem_init();
extern void collectible_func10();
extern void collectible_func0F();
extern void collectible_func0E();
extern void collectible_render2();
extern void collectible_modelMtxFn();
extern void collectible_func0B();
extern void collectible_setScale();
extern void collectible_getExtraSize();
extern void collectible_getObjectTypeId();
extern void collectible_free();
extern void collectible_render();
extern void collectible_hitDetect();
extern void collectible_update();
extern void collectible_init();
extern void collectible_release();
extern void collectible_initialise();
extern void setuppoint_init();
extern void siderepel_getExtraSize();
extern void siderepel_free();
extern void siderepel_init();
/* .data table (attributed from auto object; pointer tables regenerate ADDR32 relocs) */

ObjectDescriptor11WithPadding gCheckpoint4ObjDescriptor = {
    {
        0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
        (ObjectDescriptorCallback)checkpoint4_initialise,
        (ObjectDescriptorCallback)checkpoint4_release,
        0,
        (ObjectDescriptorCallback)checkpoint4_init,
        (ObjectDescriptorCallback)checkpoint4_update,
        (ObjectDescriptorCallback)checkpoint4_hitDetect,
        (ObjectDescriptorCallback)checkpoint4_render,
        (ObjectDescriptorCallback)checkpoint4_free,
        (ObjectDescriptorCallback)checkpoint4_getObjectTypeId,
        checkpoint4_getExtraSize,
        (ObjectDescriptorCallback)checkpoint4_setScale,
    },
    0,
};

void* gSideloadObjDescriptor[14] = { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00090000, (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, sideload_update, (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00000000 };
void* gSiderepelObjDescriptor[14] = { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00090000, (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, siderepel_init, (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, siderepel_free, (void*)0x00000000, siderepel_getExtraSize };
void* gSetuppointObjDescriptor[14] = { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00090000, (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, setuppoint_init, (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00000000 };
u8 lbl_80320C58[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
void* gCollectibleObjDescriptor[21] = { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00100000, collectible_initialise, collectible_release, (void*)0x00000000, collectible_init, collectible_update, collectible_hitDetect, collectible_render, collectible_free, collectible_getObjectTypeId, collectible_getExtraSize, collectible_setScale, collectible_func0B, collectible_modelMtxFn, collectible_render2, collectible_func0E, collectible_func0F, collectible_func10 };
u8 lbl_80320CB8[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
void* gMagicGemObjDescriptor[14] = { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00090000, (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, magicgem_init, magicgem_update, (void*)0x00000000, magicgem_render, magicgem_free, (void*)0x00000000, magicgem_getExtraSize };
