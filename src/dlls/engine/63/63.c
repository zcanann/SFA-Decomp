#include "main/texture.h"
#include "sys/objects.h"
#include "main/dll/ppcwgpipe_struct.h"
#include "dlls/object_descriptor.h"
#include "main/model_engine.h"
#include "main/objtype.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/printf.h"
#include "main/dll/dll_003F_dll3f.h"

char sDll3FTimerFormat[] = "%2d";

#define DLL3F_TEXTURE_ID 0x47A

void* gDll3FTexture;

void dll_3F_updateTimerReadout(void* obj)
{
    char buf[12];
    f32 maxDist;
    int start;
    int elapsed;
    int total;
    void* player;
    GameObject* nearest;

    maxDist = 1e+04f;
    start = 0;
    elapsed = 0;
    total = 0;
    if (gameTimerIsRunning())
    {
        gameTimerRun(obj);
    }
    player = Obj_GetPlayerObject();
    nearest = objGetNearestTypeTo(9, player, &maxDist);
    if (nearest != NULL)
    {
        ((void (*)(void*, int*, int*, int*))(*(void***)nearest->anim.dll)[21])(nearest, &start, &elapsed,
                                                                                              &total);
    }
    elapsed = total - (elapsed - start);
    if (elapsed < 0)
    {
        elapsed = 0;
    }
    sprintf(buf, sDll3FTimerFormat, elapsed);
}

void dll_3F_frameEnd_nop(void)
{
}

int dll_3F_frameStart_ret_0(void)
{
    return 0;
}

void dll_3F_release(void) {
    textureFree(gDll3FTexture);
}

void dll_3F_initialise(void)
{
    gDll3FTexture = textureLoadAsset(DLL3F_TEXTURE_ID);
}

PPCWGPipe GXWGFifo : (0xCC008000);

ObjectDescriptor6 dll_3F_funcs = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_6_SLOTS,
    (ObjectDescriptorCallback)dll_3F_initialise,
    (ObjectDescriptorCallback)dll_3F_release,
    0,
    (ObjectDescriptorCallback)dll_3F_frameStart_ret_0,
    (ObjectDescriptorCallback)dll_3F_frameEnd_nop,
    (ObjectDescriptorCallback)dll_3F_updateTimerReadout,
};
