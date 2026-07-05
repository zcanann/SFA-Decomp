#include "main/asset_load.h"
#include "main/audio/sfx.h"
#include "main/obj_placement.h"
#include "main/camera_interface.h"
#include "main/game_ui_interface.h"
#include "main/objseq.h"
#include "main/sky_80080E58_shared.h"
#include "main/pad.h"
#include "main/sfa_extern_decls.h"
#include "main/maketex.h"
extern int getTableFileEntry(int fileId, int index, int* out);
extern int loadAndDecompressDataFile(int id, void* buf, int blockOff, int len, int a, int b, int c);
extern int strncmp(const char* a, const char* b, u32 n);
extern void fn_80137948(char* fmt, ...);
extern char sObjLoadAnimdataNullACRomTabWarning[];
extern char sSeqAAnimDataTag;
extern char sSeqBAnimDataTag;

/* GameObject::objectFlags bit: object is bound to an active sequence (set when
   it becomes a seq callback target, cleared on release; tested elsewhere as the
   "under sequence control / blocked from normal update" gate). */
#define OBJECT_OBJFLAG_SEQ_ATTACHED 0x1000

extern u8 lbl_80399E50[];
extern int lbl_803DD064;
extern int lbl_803DD084;
extern s16 lbl_803DD060;
extern s16 lbl_803DD062;
extern char sObjSequenceMissingObjectFormat[];
extern s8 gObjSeqMsgSendModes[];
extern int gObjSeqMsgIds[];
extern f32 gObjSeqMsgNearbyRadius;
extern s8 gObjSeqJumpLatch[];
int objSeqExecCmd06(u8* obj, u8* sourceObj, u8* seq, int cmd, s8 flag);
extern void fn_80295E90(void* obj, int idx);
extern void fn_802967E0(void* obj, int idx);
extern void fn_8029672C(void* obj, int idx);
extern void Obj_SetActiveModelIndex(u8* obj, int idx);
extern void playerLock(void* player, int mode);
extern void setMotionBlur(u8 enabled, f32 amount);
extern void Rcp_SetMonochromeFilterEnabled(int enabled);
extern void gameTimerInit(s8 flags, int minutes);
extern void timerSetToCountUp(void);
extern void gameTimerStop(void);
extern void Camera_EnableViewYOffset(void);
extern f32 Vec_xzDistance(f32* a, f32* b);
extern void CameraShake_Start(f32 magnitude, f32 duration, f32 falloff);
extern int seqStreamFn_8008023c(int slot);
extern int* seqStreamLookupFn_8007fff8(void* table, int count, int key);
extern int AudioStream_Play(int id, void (*preparedCallback)(void));

extern int gObjSeqStreamTableB[];
extern int lbl_803DB718;
extern int lbl_803DB728;
extern f32 gObjSeqShakeAmplitude;
extern u32 gObjSeqCurrentTrackId;
extern s16 gObjSeqStreamStopped;
extern f32 gObjSeqTexScrollScale;
extern f32 gObjSeqShakeMaxDist;
extern f32 gObjSeqShakeFalloffStart;
extern f32 gObjSeqShakeFalloffRange;
extern f32 lbl_803DD0F4;
extern f32 lbl_803DD0F0;
extern f32 lbl_803DD0EC;
extern f32 gObjSeqFovOverrideValue;
extern f32 gObjSeqCameraFov;
extern f32 gObjSeqSavedCamPosX;
extern f32 gObjSeqSavedCamPosY;
extern f32 gObjSeqSavedCamPosZ;
extern f32 gObjSeqSavedCamFov;
extern int gObjSeqSavedCamPitch;
extern int gObjSeqSavedCamYaw;
extern int gObjSeqSavedCamRoll;
extern f32 lbl_803DEFF4;
extern f32 lbl_803DEFF8;
extern f32 lbl_803DEFFC;
extern u8 gObjSeqFovOverrideActive;
extern u8 curSeqNo;
extern void Obj_TransformWorldPointToLocal(f32 wx, f32 wy, f32 wz, f32* x, f32* y, f32* z, void* m);
extern u8 lbl_8039944C[];
extern int lbl_803DD0C0;
extern s16 lbl_803DD08A;
extern f32 lbl_803DF030;
extern f32 gObjSeqDefaultFadeRate;
extern f32 MTRCallback;
extern f32 DBGCallback;
extern f32 gObjSeqCurvePosOffsetX;
extern f32 gObjSeqCurvePosOffsetY;
extern f32 gObjSeqCurvePosOffsetZ;
extern f32 lbl_803DF038;
extern f32 gObjSeqDegreesToAngle;
extern f32 lbl_803DF040;
extern f32 lbl_803DF044;
extern int* seqFn_800394a0(void);
extern u8 lbl_803DB411;
extern int objSeqObjs;
extern int lbl_803DB714;
extern int lbl_803DB71C;
extern u8 lbl_803DD0D9;
extern u8 lbl_803DD078;
extern s16 lbl_8030ECF8[];
extern int fn_80296C2C(void* obj);
extern void fn_80297254(void* obj);
extern void fn_8029726C(void* obj);
extern void fn_80297284(void* obj);
extern void gameTextLoadTaskText(int taskId);

extern int lbl_803DB724;
extern f32 lbl_803DD074;
extern f32 RecvDataLeng;
extern f32 SendMailData;
extern void setJoypadDisabled(void);
extern u8 lbl_803DD111;
extern u8 lbl_803DD112;
extern f32 lbl_803DF02C;
extern void ObjModel_SetBlendChannelTargets(void* action, int mode, int target, int channel, int p5, f32 t);
extern void warpToMap(int idx, s8 transType);
int ObjSeq_ExecuteActionCommand(u8* obj, u8* action, u8** cmd, int flags, void* out);
void* ObjSeq_ToggleCommand3Target(u8 * obj, u8 * seq, u8 * src);

typedef struct CamRequest
{
    s16 rot[3];
    u8 pad6[6];
    f32 posB[3];
    f32 pos[3];
    u8 pad24[0x90];
    f32 fov;
    u8 padB8[0x8c];
} CamRequest;

typedef struct CamFloats
{
    f32 a;
    f32 b;
    s16 c;
} CamFloats;

typedef struct CamMode
{
    int mode;
    u8 flag;
} CamMode;

typedef struct SeqByte136
{
    u8 modelSlot : 4;
    u8 pad3 : 1;
    u8 mapEvent : 1;
    u8 rest : 2;
} SeqByte136;

int ObjSeq_update(u8* obj, f32 t);

typedef struct SeqRunFlags
{
    u8 useWorldSpace : 1;
} SeqRunFlags;

extern SeqRunFlags lbl_803DD0B4;
extern u8* lbl_803DD07C;

static inline u8* ObjSeq_GetActiveModel(u8* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (u8*)objAnim->banks[objAnim->bankIndex];
}

void ObjSeq_setCamVars(int camA, int camB, int camC, int camD)
{
    gObjSeqCamMode = camA;
    gObjSeqCamModeArgB = camB;
    gObjSeqCamModeArgC = camC;
    gObjSeqCamModeArgD = camD;
}

#pragma dont_inline on
int objSeqFindLabel(u8* seq, int label)
{
    int commandCount;
    int commandIndex;
    int repeatCount;
    u32 packed;
    int currentLabel;
    u8* command;

    currentLabel = 0;
    commandIndex = 0;
    commandCount = ((ObjSeqState*)seq)->cmdCount;
    while (commandIndex < commandCount)
    {
        command = ((ObjSeqState*)seq)->cmds + commandIndex * 4;
        if ((s8)command[0] == 0)
        {
            currentLabel = *(s16*)(command + 2);
        }
        else if ((s8)command[0] == 0xb)
        {
            if (*(s16*)(command + 2) > 0)
            {
                packed = *(u32*)(command + 4);
                if ((int)(packed & 0x3f) == 9 && (int)(packed >> 16) == label)
                {
                    return currentLabel;
                }
                commandIndex += *(s16*)(command + 2);
            }
        }
        currentLabel += command[1];
        commandIndex++;
    }
    return -1;
}
#pragma dont_inline reset

#pragma dont_inline on
int objSeqFindConditional(u8* seq, u8* seqState)
{
    int currentLabel;
    int commandIndex;
    u8* command;
    u32 packed;

    currentLabel = -1;
    commandIndex = 0;
    while (commandIndex < ((ObjSeqState*)seq)->cmdCount)
    {
        command = ((ObjSeqState*)seq)->cmds + commandIndex * 4;
        if ((s8)command[0] == 0)
        {
            currentLabel = *(s16*)(command + 2);
        }
        else if ((s8)command[0] == 0xb)
        {
            if (*(s16*)(command + 2) > 0)
            {
                packed = *(u32*)(command + 4);
                if ((int)(packed & 0x3f) == 4 &&
                    ObjSeq_EvaluateCondition((packed >> 6) & 0x3ff, seq, *(int*)(seqState + 0x4c)) != 0)
                {
                    currentLabel -= 10;
                    if (currentLabel < 0)
                    {
                        currentLabel = 0;
                    }
                    return currentLabel;
                }
                commandIndex += *(s16*)(command + 2);
            }
        }
        currentLabel += command[1];
        commandIndex++;
    }
    return -1;
}
#pragma dont_inline reset

void objCallSeqFn(u8* obj, u8* sourceObj, u8* seq, int action)
{
    int callbackResult;
    s8 actionSlot;
    int movementState;
    int flags;
    u8* sourceModel;

    (void)action;

    sourceModel = *(u8**)(sourceObj + 0x4c);
    ((GameObject*)obj)->anim.previousLocalPosX = ((GameObject*)obj)->anim.localPosX;
    ((GameObject*)obj)->anim.previousLocalPosY = ((GameObject*)obj)->anim.localPosY;
    ((GameObject*)obj)->anim.previousLocalPosZ = ((GameObject*)obj)->anim.localPosZ;
    ((GameObject*)obj)->anim.previousWorldPosX = ((GameObject*)obj)->anim.worldPosX;
    ((GameObject*)obj)->anim.previousWorldPosY = ((GameObject*)obj)->anim.worldPosY;
    ((GameObject*)obj)->anim.previousWorldPosZ = ((GameObject*)obj)->anim.worldPosZ;

    if (((GameObject*)obj)->animEventCallback != NULL)
    {
        callbackResult = (*(int (**)(u8*, u8*, u8*, int))(obj + 0xbc))(obj, sourceObj, seq, action);
        if (callbackResult == 4)
        {
            gObjSeqStop = 1;
        }
        else if (callbackResult != 0)
        {
            actionSlot = ((ObjSeqState*)seq)->slot;
            if (gObjSeqSlotResults[actionSlot] < 2)
            {
                gObjSeqSlotResults[actionSlot] = callbackResult;
            }
        }
        ((ObjSeqState*)seq)->eventCount = 0;
        ((ObjSeqState*)seq)->unk80 = 0;
    }
    else
    {
        if ((s8)((ObjSeqState*)seq)->unk7B != 0)
        {
            ((ObjSeqState*)seq)->movementState = 0;
            return;
        }

        movementState = (s8)((ObjSeqState*)seq)->movementState;
        if (movementState >= 4)
        {
            if (ObjSeq_func20(obj, seq, 6, 0x1e, 0x50, -1, -1) != 0)
            {
                actionSlot = ((ObjSeqState*)seq)->slot;
                if (gObjSeqSlotResults[actionSlot] < 2)
                {
                    gObjSeqSlotResults[actionSlot] = 1;
                }
            }
        }
        else if (movementState != 0)
        {
            if (movementState != 2)
            {
                ((ObjSeqState*)seq)->posOffsetScale = lbl_803DEFC8;
                ((ObjSeqState*)seq)->posOffsetX =
                    ((GameObject*)obj)->anim.localPosX - ((GameObject*)sourceObj)->anim.localPosX;
                ((ObjSeqState*)seq)->posOffsetY =
                    ((GameObject*)obj)->anim.localPosY - ((GameObject*)sourceObj)->anim.localPosY;
                ((ObjSeqState*)seq)->posOffsetZ =
                    ((GameObject*)obj)->anim.localPosZ - ((GameObject*)sourceObj)->anim.localPosZ;
                ((ObjSeqState*)seq)->movementState = 2;
            }
            if ((s8)sourceModel[0x20] == 1)
            {
                ((ObjSeqState*)seq)->posOffsetDecay = lbl_803DF024;
                actionSlot = ((ObjSeqState*)seq)->slot;
                if (gObjSeqSlotResults[actionSlot] < 2)
                {
                    gObjSeqSlotResults[actionSlot] = 1;
                }
            }
            ((ObjSeqState*)seq)->posOffsetScale = ((ObjSeqState*)seq)->posOffsetScale - ((ObjSeqState*)seq)->
                posOffsetDecay * timeDelta;
            if (((ObjSeqState*)seq)->posOffsetScale <= lbl_803DEFB0)
            {
                ((ObjSeqState*)seq)->movementState = 0;
            }
        }
    }

    flags = obj[0xaf];
    flags &= ~7;
    obj[0xaf] = flags;
    Obj_GetWorldPosition(obj, (f32*)((int)obj + 0x18), (f32*)((int)obj + 0x1c),
                         (f32*)((int)obj + 0x20));
    if (((GameObject*)obj)->anim.hitReactState != NULL)
    {
        (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->lastHitObject = 0;
        (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->priorityHitCount = 0;
    }
    if (*(void**)(obj + 0x58) != NULL)
    {
        *(u8*)(*(u8**)(obj + 0x58) + 0x10f) = 0;
    }
}

void* ObjSeq_ToggleCommand3Target(u8* obj, u8* seq, u8* src)
{
    void* result;
    u8* activeObj;
    u8* entry;
    int j;
    u8* slotBase;
    int slotOff;
    u8* seqObj;
    f32 groundY[2];

    result = obj;
    *(s8*)&((ObjSeqState*)seq)->unk79 = (s8)(((ObjSeqState*)seq)->unk79 ^ 1);
    if ((s8)((ObjSeqState*)seq)->unk79 != 0)
    {
        ObjSeq_ResolveAndAssignTargetObject(obj);
        seqObj = *(u8**)seq;
        if (seqObj != NULL)
        {
            result = seqObj;
            *(void**)(seqObj + 0xc0) = obj;
            ((GameObject*)seqObj)->objectFlags |= OBJECT_OBJFLAG_SEQ_ATTACHED;
            ((ObjSeqState*)seq)->callbackContext = seqObj;

            activeObj = *(u8**)seq;
            j = 0;
            slotOff = (s8)((ObjSeqState*)seq)->slot * 0x80;
            slotBase = lbl_80396918 + slotOff;
            entry = slotBase;
            for (; j < 16; j++)
            {
                if (*(u8**)entry == NULL || *(u8**)entry == activeObj)
                {
                    break;
                }
                entry += 8;
            }
            *(u8**)(slotBase + j * 8) = activeObj;
            *(u8**)((u8*)(int)lbl_80396918 + slotOff + j * 8 + 4) = obj;
        }
    }
    else
    {
        if (((ObjSeqState*)seq)->targetObj != NULL)
        {
            if ((((ObjSeqState*)seq)->flags & 1) != 0)
            {
                ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.localPosX;
                ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY;
                ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.localPosZ;
                ObjSeq_UpdateCurvePosition(obj, seq);
            }
            if ((s8)((ObjSeqState*)seq)->unk7A == 1 &&
                hitDetectFn_800658a4(obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                     ((GameObject*)obj)->anim.localPosZ, groundY, 0) == 0)
            {
                ((GameObject*)obj)->anim.localPosY =
                    ((GameObject*)obj)->anim.localPosY +
                    ((((GameObject*)obj)->anim.localPosY - groundY[0]) - *(f32*)(src + 0xc));
            }
            if ((((ObjSeqState*)seq)->flags & 2) != 0)
            {
                *(s16*)obj += ((ObjSeqState*)seq)->heading;
            }
            ((GameObject*)obj)->pendingParentObj = NULL;
            ((GameObject*)obj)->objectFlags &= ~OBJECT_OBJFLAG_SEQ_ATTACHED;
            ((ObjSeqState*)seq)->targetObj = NULL;
            result = obj;
        }
    }
    return result;
}

void ObjSeq_run(void)
{
    int ok;
    int keepCount;
    void** objects;
    int matchCount;
    void** objPtr;
    u8* base;
    u8* cmd;
    s16* keepWalk;
    s16* keepBase;
    int count;
    int i;
    int index;
    int xrot;
    u8* model;
    u8* seqp;
    u8* candidate;
    u8** mp;
    int n;
    int k;
    s8* pending;
    u8* results;
    u8* actions;
    f32* dists;
    f32* frames;
    u8* marks;
    s8 frames8;
    u8* matched[0x28];
    s16 keepBuf[0x5a];
    int objectCount;
    void* unused;

    base = lbl_80396918;
    objects = ObjList_GetObjects(&unused, &objectCount);
    if (lbl_803DD060 != lbl_803DD062)
    {
        lbl_803DD062 = lbl_803DD060;
    }

    pending = (s8*)(base + 0x39e8);
    results = base + 0x3bf4;
    actions = base + 0x3c4c;
    dists = (f32*)(base + 0x3740);
    frames = (f32*)(base + 0x3894);
    marks = base + 0x338c;
    frames8 = framesThisStep;

    for (i = 0; i < 0x55; i++)
    {
        *pending = 0;
        if ((s8) * results != 0 && (s8) * actions == 0)
        {
            *pending = frames8;
        }
        *actions = *results;
        *results = 0;
        *frames = *dists;
        *dists = lbl_803DEFF0;
        if (*marks == 2)
        {
            *marks = 1;
        }
        else
        {
            *marks = 0;
        }
        pending++;
        results++;
        actions++;
        dists++;
        frames++;
        marks++;
    }

    count = gObjSeqBgCmdCount;
    keepCount = 0;
    cmd = base + count * 6;
    cmd += 0x2a80;
    keepBase = keepBuf;
    keepWalk = keepBase;
    while (count > 0)
    {
        cmd -= 6;
        count--;
        index = *(s16*)cmd;
        xrot = *(s16*)(cmd + 2);
        i = 0;
        base[index + 0x3b44] = 0;
        base[index + 0x3b9c] = 0;
        base[index + 0x3a40] = 0;
        matchCount = 0;
        ok = 1;
        objPtr = objects;
        for (; i < objectCount; i++)
        {
            candidate = *objPtr;
            if (((GameObject*)candidate)->anim.classId == 0x10)
            {
                model = *(u8**)(candidate + 0x4c);
                seqp = *(u8**)(candidate + 0xb8);
                if (model != NULL && (s8)model[0x1f] == index)
                {
                    if (*(s16*)(model + 0x1c) >= 4 &&
                        ObjSeq_FindTargetObject(candidate) == NULL)
                    {
                        ok = 0;
                        fn_80137948(sObjSequenceMissingObjectFormat,
                                    *(s16*)(model + 0x1c) - 4);
                    }
                    else
                    {
                        ((ObjSeqState*)seqp)->targetObj = NULL;
                    }
                    if (matchCount < 0x28)
                    {
                        matched[matchCount++] = candidate;
                    }
                }
            }
            objPtr++;
        }

        mp = matched;
        for (n = 0; n < matchCount; n++)
        {
            candidate = *mp;
            model = *(u8**)(candidate + 0x4c);
            if (model != NULL && (s8)model[0x1f] == index)
            {
                seqp = *(u8**)(candidate + 0xb8);
                if (ok != 0)
                {
                    ((ObjSeqState*)seqp)->unk7E = 2;
                    ((ObjSeqState*)seqp)->unk5E = xrot;
                    ObjSeq_update(candidate, lbl_803DEFC8);
                    Obj_GetWorldPosition(candidate, &((GameObject*)candidate)->anim.worldPosX,
                                         &((GameObject*)candidate)->anim.worldPosY,
                                         &((GameObject*)candidate)->anim.worldPosZ);
                }
                else
                {
                    ((ObjSeqState*)seqp)->unk7E = 3;
                }
            }
            mp++;
        }

        if (ok == 0)
        {
            *keepWalk = index;
            keepWalk += 3;
            keepBuf[keepCount++ * 3 + 1] = xrot;
        }
    }

    for (k = 0; k < keepCount; k++)
    {
        ((s16*)(base + 0x2a80))[k * 3] = keepBase[0];
        ((s16*)(base + 0x2a80))[k * 3 + 1] = keepBase[1];
        keepBase += 3;
    }
    gObjSeqBgCmdCount = keepCount;
}

void objSeqDoBgCmds0D(u8* seq, u8* obj, int skipSpawns)
{
    ObjSeqBgCmd* cmd;
    int cmdObj;
    int cmdParam;
    void* resource;
    int transitionSlot;
    int uiId;

    if (lbl_803DD090 != 0 && ((GameObject*)obj)->seqIndex != (s8)((ObjSeqState*)seq)->slot)
    {
        (*gGameUIInterface)->setHudFields(0, 0, 0);
    }

    while (lbl_803DD113 > 0)
    {
        lbl_803DD113--;
        cmd = &lbl_8039A5BC[lbl_803DD113];
        cmdParam = cmd->param;
        cmdObj = cmd->object;

        switch (cmd->opcode)
        {
        case 3:
            if ((u8)skipSpawns == 0)
            {
                (*gPartfxInterface)->spawnObject((void*)cmdObj, cmdParam, NULL, 0x10000, -1, NULL);
            }
            break;
        case 4:
            if ((u8)skipSpawns == 0)
            {
                return0xFFFF_80008B6C(cmdObj, 0, 0, 1, -1, (u8)cmdParam, 0);
            }
            break;
        case 5:
            if ((u8)skipSpawns == 0)
            {
                resource = Resource_Acquire((u16)(cmdParam + 0xab), 1);
                if (resource != NULL)
                {
                    (*(void (**)(int, int, int, int, int, int, int))((char*)*(int**)resource + 0x4))(
                        cmdObj, 0, 0, 1, -1, (u8)cmdParam, 0);
                }
                if (resource != NULL)
                {
                    Resource_Release(resource);
                }
            }
            break;
        case 9:
            if ((u8)skipSpawns == 0)
            {
                switch (cmdParam & 0x2f)
                {
                case 6:
                    transitionSlot = (cmdParam & 0xfc0) >> 4;
                    (*gScreenTransitionInterface)->start(transitionSlot, 3);
                    break;
                case 7:
                    transitionSlot = (cmdParam & 0xfc0) >> 4;
                    (*gScreenTransitionInterface)->step(transitionSlot, 3);
                    break;
                case 8:
                    transitionSlot = (cmdParam & 0xfc0) >> 4;
                    (*gScreenTransitionInterface)->start(transitionSlot, 2);
                    break;
                case 9:
                    transitionSlot = (cmdParam & 0xfc0) >> 4;
                    (*gScreenTransitionInterface)->step(transitionSlot, 2);
                    break;
                case 0xb:
                    transitionSlot = (cmdParam & 0xfc0) >> 4;
                    (*gScreenTransitionInterface)->start(transitionSlot, 4);
                    break;
                case 0xc:
                    transitionSlot = (cmdParam & 0xfc0) >> 4;
                    (*gScreenTransitionInterface)->stepWithBlend(transitionSlot, 4, lbl_803DF028);
                    break;
                }
            }
            break;
        case 0xb:
            GameBit_Set(cmdParam, 1);
            break;
        case 0xc:
            GameBit_Set(cmdParam, 0);
            break;
        case 0xd:
            if ((u8)skipSpawns == 0)
            {
                uiId = lbl_8030EDA4[cmdParam];
                (*gGameUIInterface)->setHudFields(uiId, 0, 0);
                if (lbl_8030EDA4[cmdParam] != -1)
                {
                    lbl_803DD090 = 1;
                }
                else
                {
                    lbl_803DD090 = 0;
                }
            }
            break;
        }
    }
}

int seqDoSubCmd0B(u8* obj, u8* sourceObj, u8* seq, u8* cmdsArg, s16 xrot, s16 countArg,
                  s8 flag1, s8 flag2)
{
    u8* cmds;
    int count;
    int opcode;
    int arg10;
    int top16;
    int subId;
    int i;
    int freeSlot;
    u32 packed;
    int result;
    int j;
    int found;
    u8 v;
    int n;
    int slot;

    i = 0;
    cmds = cmdsArg;
    count = countArg;
    for (; i < count; i++)
    {
        packed = *(u32*)cmds;
        opcode = packed & 0x3f;
        arg10 = (packed >> 6) & 0x3ff;
        top16 = packed >> 16;
        if (opcode == 2 || opcode == 3)
        {
            if ((top16 & 0x8000) != 0)
            {
                top16 |= 0xffff0000;
            }
            subId = arg10;
            arg10 = 0;
        }

        result = 0;
        switch (opcode)
        {
        case 6:
            if (objSeqExecCmd06(obj, sourceObj, seq, arg10 | (top16 << 8), flag2) == 0)
            {
                return 1;
            }
            result = -1;
            arg10 = 0;
            break;
        case 7:
            if (sourceObj != obj)
            {
                switch ((s8)gObjSeqMsgSendModes[arg10])
                {
                case 1:
                    ObjMsg_SendToObjects(0, 2, obj, gObjSeqMsgIds[arg10], obj);
                    break;
                case 2:
                    ObjMsg_SendToNearbyObjects(0, gObjSeqMsgNearbyRadius, 2, obj,
                                               gObjSeqMsgIds[arg10], obj);
                    break;
                default:
                    ObjMsg_SendToObject(sourceObj, gObjSeqMsgIds[arg10], obj, 0);
                    break;
                }
            }
            result = -1;
            arg10 = 0;
            break;
        case 8:
            if (flag2 == 0)
            {
                found = 0;
                freeSlot = -1;
                for (j = 0; j < 10; j++)
                {
                    v = seq[j + 0x12c];
                    if (v == arg10)
                    {
                        found = 1;
                    }
                    if (v == 0)
                    {
                        freeSlot = j;
                    }
                }
                if (found == 0 && freeSlot != -1)
                {
                    seq[freeSlot + 0x12c] = arg10;
                    *(s16*)(seq + freeSlot * 2 + 0x118) =
                        objSeqFindLabel(seq, top16);
                }
                result = 0;
            }
            break;
        case 9:
            break;
        default:
            result = ObjSeq_EvaluateCondition(arg10, seq, *(int*)&((GameObject*)obj)->anim.placementData);
            break;
        }

        if (result > 0 && flag1 == 0)
        {
            switch (opcode)
            {
            case 1:
                if (flag2 != 0)
                {
                    break;
                }
                slot = (s8)((ObjSeqState*)seq)->slot;
                if ((s8)gObjSeqJumpLatch[slot] == 0)
                {
                    gObjSeqJumpLatch[slot] = 1;
                    ((ObjSeqState*)seq)->curFrame = top16;
                    ((ObjSeqState*)seq)->prevFrame = ((ObjSeqState*)seq)->curFrame;
                }
                return 1;
            case 10:
                if (flag2 != 0)
                {
                    break;
                }
                slot = (s8)((ObjSeqState*)seq)->slot;
                if ((s8)gObjSeqJumpLatch[slot] == 0)
                {
                    gObjSeqJumpLatch[slot] = 1;
                    ((ObjSeqState*)seq)->curFrame = objSeqFindLabel(seq, top16);
                    ((ObjSeqState*)seq)->prevFrame = ((ObjSeqState*)seq)->curFrame;
                }
                return 1;
            case 2:
                switch (subId)
                {
                case 0:
                    ((ObjSeqState*)seq)->unk80 = top16;
                    n = ((ObjSeqState*)seq)->eventCount;
                    if ((u32)n < 10)
                    {
                        ((ObjSeqState*)seq)->eventCount += 1;
                        ((ObjSeqState*)seq)->eventIds[n] = top16;
                    }
                    break;
                case 1:
                    ((ObjSeqState*)seq)->seqCounter = top16;
                    break;
                case 3:
                    seqGlobal1 = top16;
                    break;
                case 4:
                    seqGlobal2 = top16;
                    break;
                case 5:
                    gObjSeqBoolFlags[(s8)((ObjSeqState*)seq)->slot] = top16;
                    break;
                case 6:
                    GameBit_Set(((ObjSeqState*)seq)->gameBit, top16 != 0);
                    break;
                case 2:
                    break;
                }
                break;
            case 3:
                if (flag2 != 0)
                {
                    break;
                }
                switch (subId)
                {
                case 0:
                    ((ObjSeqState*)seq)->seqCounter = ((ObjSeqState*)seq)->seqCounter + top16;
                    break;
                case 1:
                    break;
                }
                break;
            case 4:
                if (flag2 != 0)
                {
                    break;
                }
                ((ObjSeqState*)seq)->curFrame = xrot;
                ((ObjSeqState*)seq)->prevFrame = xrot;
                *(s8*)&((ObjSeqState*)seq)->unk7C = (s8)(arg10 + 1);
                gObjSeqJumpLatch[(s8)((ObjSeqState*)seq)->slot] = 1;
                return 1;
            case 5:
                if (flag2 != 0)
                {
                    break;
                }
                return 0;
            case 0:
            case 6:
            case 7:
            case 8:
            case 9:
                break;
            }
        }
        cmds += 4;
    }
    return 0;
}

void ObjSeq_updateCamera(void)
{
    CamRequest block;
    CamFloats fblock;
    CamMode mode47;
    CamMode mode48;
    void* groupObjs;
    u8* obj;
    u8* model;
    u8* camObj;
    f32 x;
    f32 y;
    f32 z;
    s16 pitch;
    s16 yaw;
    s16 roll;
    int code;

    obj = lbl_803DD0B8;
    if (obj != NULL)
    {
        model = *(u8**)&((GameObject*)obj)->anim.placementData;
        if (lbl_803DD0F8 != 0)
        {
            x = lbl_803DD0F4;
            y = lbl_803DD0F0;
            z = lbl_803DD0EC;
        }
        else
        {
            x = ((GameObject*)obj)->anim.worldPosX;
            y = ((GameObject*)obj)->anim.worldPosY;
            z = ((GameObject*)obj)->anim.worldPosZ;
        }
        pitch = *(s16*)obj;
        yaw = ((GameObject*)obj)->anim.rotY;
        roll = ((GameObject*)obj)->anim.rotZ;
        if (((GameObject*)obj)->anim.parent != NULL)
        {
            pitch = (s16)(pitch + *(s16*)*(u8**)&((GameObject*)obj)->anim.parent);
        }
        lbl_803DD0DC = lbl_803DEFC8;
        if ((s8)gObjSeqCameraActive == 0)
        {
            block.pos[0] = x;
            block.pos[1] = y;
            block.pos[2] = z;
            block.rot[0] = (s16)(0x8000 - pitch);
            block.rot[1] = (s16) - yaw;
            block.rot[2] = roll;
            if ((s8)gObjSeqFovOverrideActive != 0)
            {
                block.fov = gObjSeqFovOverrideValue;
                gObjSeqCameraFov = gObjSeqFovOverrideValue;
            }
            else
            {
                block.fov = gObjSeqCameraFov;
            }
            (*gCameraInterface)->setMode(0x4c, 0, 1, 0x144, &block, model[0x24], 0xff);
            gObjSeqCameraActive = 1;
        }
        else
        {
            camObj = (*gCameraInterface)->getCamera();
            *(f32*)(camObj + 0x18) = x;
            *(f32*)(camObj + 0x1c) = y;
            *(f32*)(camObj + 0x20) = z;
            Obj_TransformWorldPointToLocal(*(f32*)(camObj + 0x18), *(f32*)(camObj + 0x1c),
                                           *(f32*)(camObj + 0x20), (f32*)(camObj + 0xc),
                                           (f32*)(camObj + 0x10), (f32*)(camObj + 0x14),
                                           *(void**)(camObj + 0x30));
            *(s16*)camObj = (s16)(0x8000 - pitch);
            *(s16*)(camObj + 2) = (s16) - yaw;
            *(s16*)(camObj + 4) = roll;
            if ((s8)gObjSeqFovOverrideActive != 0)
            {
                *(f32*)(camObj + 0xb4) = gObjSeqFovOverrideValue;
                gObjSeqCameraFov = gObjSeqFovOverrideValue;
            }
            else
            {
                *(f32*)(camObj + 0xb4) = gObjSeqCameraFov;
            }
            gObjSeqSavedCamPosX = *(f32*)(camObj + 0x18);
            gObjSeqSavedCamPosY = *(f32*)(camObj + 0x1c);
            gObjSeqSavedCamPosZ = *(f32*)(camObj + 0x20);
            gObjSeqSavedCamPitch = *(s16*)camObj;
            gObjSeqSavedCamYaw = *(s16*)(camObj + 2);
            gObjSeqSavedCamRoll = *(s16*)(camObj + 4);
            gObjSeqSavedCamFov = *(f32*)(camObj + 0xb4);
        }
    }
    else
    {
        if ((s8)gObjSeqCameraActive != 0)
        {
            if (lbl_803DD064 == 0)
            {
                switch (gObjSeqCamMode)
                {
                case 0x47:
                    mode47.mode = gObjSeqCamModeArgB;
                    mode47.flag = gObjSeqCamModeArgC;
                    (*gCameraInterface)->setMode(0x47, 1, 3, 8, &mode47, gObjSeqCamModeArgD, 0xff);
                    break;
                case 0x48:
                    mode48.mode = gObjSeqCamModeArgB;
                    if ((code = gObjSeqCamModeArgD) == 0)
                    {
                        mode48.flag = 1;
                    }
                    (*gCameraInterface)->setMode(0x48, 1, 3, 8, &mode48, code, 0xff);
                    break;
                case 0x4a:
                    (*gCameraInterface)->setMode(0x4a, 1, 0, 0, NULL, gObjSeqCamModeArgD, 0xff);
                    break;
                case 0x4c:
                    block.posB[0] = gObjSeqSavedCamPosX;
                    block.posB[1] = gObjSeqSavedCamPosY;
                    block.posB[2] = gObjSeqSavedCamPosZ;
                    block.rot[0] = gObjSeqSavedCamPitch;
                    block.rot[1] = gObjSeqSavedCamYaw;
                    block.rot[2] = gObjSeqSavedCamRoll;
                    block.fov = gObjSeqSavedCamFov;
                    (*gCameraInterface)->setMode(0x4c, 1, 0, 0x144, &block, 0, 0xff);
                    break;
                case 0x45:
                    (*gCameraInterface)->setMode(0x45, 1, 0, 0, NULL, gObjSeqCamModeArgD, 0xff);
                    break;
                case 0x44:
                    if (gObjSeqCamModeArgB != 0)
                    {
                        fblock.a = lbl_803DEFF4;
                        fblock.b = lbl_803DEFF8;
                        fblock.c = 5;
                        (*gCameraInterface)->setMode(0x44, 1, 1, 0xc, &fblock, 0, 0xff);
                    }
                    else
                    {
                        fblock.a = lbl_803DEFF4;
                        fblock.b = lbl_803DEFF8;
                        fblock.c = 0x1e;
                        (*gCameraInterface)->setMode(0x44, 1, 0, 0xc, &fblock, 0, 0xff);
                    }
                    break;
                case 0x49:
                    (*gCameraInterface)->setMode(0x49, 1, 0, gObjSeqCamModeArgB, &gObjSeqCamModeArgC, gObjSeqCamModeArgD, 0xff);
                    break;
                case 0x53:
                    (*gCameraInterface)->setMode(0x53, 1, 0, 0, NULL, 0, 0xff);
                    break;
                case 0x56:
                    (*gCameraInterface)->setMode(0x56, 1, gObjSeqCamModeArgB, 0, NULL, 0, 0);
                    break;
                case 0x57:
                    (*gCameraInterface)->setMode(0x57, 0, 3, 0, NULL, 0, 0);
                    (*gCameraInterface)->setFocus(*(void**)ObjGroup_GetObjects(0xf, &groupObjs), 0);
                    break;
                default:
                    if (gObjSeqCamModeArgB == 0)
                    {
                        gObjSeqCamModeArgB = 1;
                    }
                    (*gCameraInterface)->setMode(0x42, 0, gObjSeqCamModeArgB, 0, NULL, gObjSeqCamModeArgD, 0xff);
                    break;
                }
            }
            gObjSeqCameraActive = 0;
            gObjSeqCameraFov = lbl_803DEFFC;
            gObjSeqCamModeArgB = 1;
            gObjSeqCamModeArgD = 0x5a;
            gObjSeqCamMode = 0x42;
            curSeqNo = 0;
        }
        else
        {
            gObjSeqCamModeArgB = 1;
            gObjSeqCamModeArgD = 0x5a;
            gObjSeqCamMode = 0x42;
        }
    }

    gObjSeqFovOverrideActive = 0;
    lbl_803DD0B8 = NULL;
    lbl_803DD0F8 = 0;
}

int objSeqExecCmd06(u8* obj, u8* sourceObj, u8* seq, int cmd, s8 flag)
{
    u8* base = lbl_80396918;
    ObjAnimComponent* sourceAnim = (ObjAnimComponent*)sourceObj;
    u32 cmdByte;
    int cmdArg = (cmd >> 8) & 0xff;
    u8* slotPtr;
    int pair[2];
    u8* player;
    u8 v;
    u8* slotFlags;
    int trackId;
    int slot;
    int off;
    int* streams;
    f32 dist;
    f32 strength;

    cmdByte = cmd & 0xff;
    switch (cmdByte)
    {
    case 2:
        if (flag != 0)
        {
            break;
        }
        pair[0] = 0x19;
        pair[1] = 0x15;
        if (((ObjSeqState*)seq)->curveId < 0)
        {
            ((ObjSeqState*)seq)->curveId =
                ((int (*)(f32, f32, f32, int*, int, int))(*gRomCurveInterface)->find)(
                    ((GameObject*)obj)->anim.localPosX,
                    ((GameObject*)obj)->anim.localPosY,
                    ((GameObject*)obj)->anim.localPosZ, pair, 2, cmdArg);
            if (((ObjSeqState*)seq)->curveId > -1)
            {
                if (((ObjSeqState*)seq)->curveInterp != NULL)
                {
                    mm_free(((ObjSeqState*)seq)->curveInterp);
                    ((ObjSeqState*)seq)->curveInterp = NULL;
                }
                ((ObjSeqState*)seq)->curveInterp = mmAlloc(0x2c, 0x11, 0);
                if (((ObjSeqState*)seq)->curveInterp != NULL)
                {
                    RomCurveInterp_InitFromNode(((ObjSeqState*)seq)->curveInterp,
                                                ((ObjSeqState*)seq)->curveId);
                }
                else
                {
                    ((ObjSeqState*)seq)->curveId = -1;
                }
            }
        }
        break;
    case 9:
        if (flag != 0)
        {
            break;
        }
        ((ObjSeqState*)seq)->unk7F |= 1;
        break;
    case 18:
        if (flag != 0)
        {
            break;
        }
        slotFlags = base + (s8)((ObjSeqState*)seq)->slot;
        v = *(slotFlags += 0x3538);
        if ((v & 0x10) != 0)
        {
            *slotFlags = v & ~0x10;
        }
        else
        {
            *slotFlags = v | 0x10;
        }
        break;
    case 14:
        if (flag != 0)
        {
            break;
        }
        if ((s8)(base + (s8)((ObjSeqState*)seq)->slot)[0x3a40] == 0)
        {
            (*gScreenTransitionInterface)->start(cmdArg, 1);
        }
        break;
    case 15:
        if (flag != 0)
        {
            break;
        }
        if ((s8)(base + (s8)((ObjSeqState*)seq)->slot)[0x3a40] == 0)
        {
            (*gScreenTransitionInterface)->step(cmdArg, 1);
        }
        break;
    case 20:
        gObjSeqCamMode = 0x47;
        gObjSeqCamModeArgB = cmdArg & 0x7f;
        gObjSeqCamModeArgC = 1;
        gObjSeqCamModeArgD = 0x78;
        break;
    case 23:
        if (flag != 0)
        {
            break;
        }
        if (cmdArg >= sourceAnim->modelInstance->modelCount)
        {
            break;
        }
        if (((GameObject*)sourceObj)->anim.classId == 1)
        {
            if (((s16*)(base + 0x3a98))[(s8)((ObjSeqState*)seq)->slot] - 1 != 0x45)
            {
                break;
            }
            if (cmdArg == 1)
            {
                cmdArg = 0;
            }
            fn_80295E90(sourceObj, cmdArg);
        }
        else
        {
            Obj_SetActiveModelIndex(sourceObj, cmdArg);
        }
        break;
    case 24:
        if (((GameObject*)sourceObj)->anim.classId == 1)
        {
            fn_802967E0(sourceObj, cmdArg);
        }
        break;
    case 25:
        if (((GameObject*)sourceObj)->anim.classId == 1)
        {
            fn_8029672C(sourceObj, cmdArg);
        }
        break;
    case 26:
        gObjSeqCamMode = 0x42;
        gObjSeqCamModeArgB = 4;
        gObjSeqCamModeArgC = 0;
        gObjSeqCamModeArgD = 0;
        break;
    case 33:
        ((ObjSeqState*)seq)->flags = ((ObjSeqState*)seq)->flags | 0x400;
        ((SeqByte136*)(seq + 0x136))->modelSlot = cmdArg;
        break;
    case 34:
        ((ObjSeqState*)seq)->flags = ((ObjSeqState*)seq)->flags & ~0x400;
        ((SeqByte136*)(seq + 0x136))->modelSlot = 0;
        break;
    case 35:
        ((SeqByte136*)(seq + 0x136))->mapEvent = 1;
        break;
    case 36:
        (*gMapEventInterface)->savePoint(0, 0, 1, getCurMapLayer());
        break;
    case 38:
        playerLock(Obj_GetPlayerObject(), cmdArg);
        break;
    case 44:
        setMotionBlur(1, cmdArg / gObjSeqTexScrollScale);
        break;
    case 45:
        setMotionBlur(0, lbl_803DEFB0);
        break;
    case 46:
        Rcp_SetMonochromeFilterEnabled(1);
        break;
    case 47:
        Rcp_SetMonochromeFilterEnabled(0);
        break;
    case 48:
        GameBit_Set(0x3b0, 1);
        getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x134, 0);
        getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x135, 0);
        getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x142, 0);
        break;
    case 49:
        GameBit_Set(0x3b0, 1);
        getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x136, 0);
        getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x137, 0);
        getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x143, 0);
        break;
    case 50:
        GameBit_Set(0x3b0, 0);
        getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x134, 0);
        getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x135, 0);
        getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x142, 0);
        envFxFn_800887cc();
        break;
    }

    switch (cmdByte)
    {
    case 0:
        gObjSeqStop = 1;
        return 0;
    case 7:
        if (flag != 0)
        {
            break;
        }
        Camera_EnableViewYOffset();
        player = Obj_GetPlayerObject();
        if (player == NULL)
        {
            break;
        }
        dist = Vec_xzDistance(&((GameObject*)player)->anim.worldPosX, &((GameObject*)obj)->anim.worldPosX);
        strength = lbl_803DF008 * (f32)(cmdArg - 7) + lbl_803DEFC8;
        if (dist < gObjSeqShakeMaxDist)
        {
            if (dist > gObjSeqShakeFalloffStart)
            {
                strength *= lbl_803DEFC8 - (dist - gObjSeqShakeFalloffStart) / gObjSeqShakeFalloffRange;
            }
            CameraShake_Start(gObjSeqShakeAmplitude * strength, gObjSeqShakeAmplitude * strength, gObjSeqShakeAmplitude);
        }
        break;
    case 10:
        gameTimerInit(0x12, cmdArg);
        break;
    case 11:
        gameTimerInit(0x11, cmdArg);
        break;
    case 12:
        timerSetToCountUp();
        break;
    case 37:
        gameTimerStop();
        break;
    case 13:
        Sfx_StopObjectChannel((u32)sourceObj, 0x7f);
        break;
    case 16:
        *(s8*)&((ObjSeqState*)seq)->unk7D = cmdArg;
        break;
    case 21:
        gObjSeqCamMode = 0x48;
        gObjSeqCamModeArgB = cmdArg & 0x7f;
        gObjSeqCamModeArgC = 1;
        gObjSeqCamModeArgD = 0x78;
        break;
    case 51:
        gObjSeqCamModeArgD = cmdArg;
        break;
    case 23:
        if (flag != 0)
        {
            break;
        }
        if (((GameObject*)sourceObj)->anim.classId == 1)
        {
            break;
        }
        if (cmdArg >= sourceAnim->modelInstance->modelCount)
        {
            break;
        }
        Obj_SetActiveModelIndex(sourceObj, cmdArg);
        break;
    case 27:
        (*gMapEventInterface)->setObjGroupStatus(sourceAnim->mapEventSlot, cmdArg, 1);
        break;
    case 28:
        (*gMapEventInterface)->setObjGroupStatus(sourceAnim->mapEventSlot, cmdArg, 0);
        break;
    case 29:
        (*gMapEventInterface)->setMapAct(sourceAnim->mapEventSlot, cmdArg);
        break;
    case 19:
        if (flag != 0)
        {
            break;
        }
        (base + (s8)((ObjSeqState*)seq)->slot)[0x3538] &= ~0x10;
        break;
    case 30:
        if (flag != 0)
        {
            break;
        }
        (base + (s8)((ObjSeqState*)seq)->slot)[0x3538] |= 0x10;
        break;
    case 31:
        (*gMapEventInterface)->clearRestartPoint();
        break;
    case 32:
        (*gMapEventInterface)->gotoRestartPoint();
        break;
    case 39:
        if (lbl_803DB720 == (s8)((ObjSeqState*)seq)->slot)
        {
            lbl_803DB728 = (int)((f32*)(base + 0x3894))[(s8)((ObjSeqState*)seq)->slot];
            gObjSeqStreamStopped = seqStreamFn_8008023c(*(s8*)&((ObjSeqState*)seq)->slot) == 0;
        }
        break;
    case 40:
        slot = *(s8*)&((ObjSeqState*)seq)->slot;
        if (base[slot + 0x3334] == 0)
        {
            trackId = (u32)(((s16*)(base + 0x3a98))[slot] - 1) & 0x3fff;
            gObjSeqCurrentTrackId = trackId;
            streams = seqStreamLookupFn_8007fff8(gObjSeqStreamTableA, 5, trackId);
            if (streams != NULL)
            {
                off = cmdArg * 4;
                if (AudioStream_Play(*(int*)((u8*)streams + off), streamCb_80080384) != 0)
                {
                    lbl_803DB720 = slot;
                }
                streams = seqStreamLookupFn_8007fff8(gObjSeqStreamTableB, 5, trackId);
                if (streams != NULL)
                {
                    lbl_803DB718 = *(int*)((u8*)streams + off);
                }
            }
        }
        break;
    }
    return 1;
}

static inline f32 ObjSeq_SampleTrackCurve(u8* seq, int track, int frame)
{
    f32 val;
    if (((ObjSeqState*)seq)->animEntries == NULL)
    {
        return lbl_803DEFB0;
    }
    val = lbl_803DEFB0;
    if (((ObjSeqState*)seq)->trackRunLength[track] != 0)
    {
        val = objCurveInterpolate(
            (ObjCurveKey*)(((ObjSeqState*)seq)->animEntries + ((ObjSeqState*)seq)->trackAnimStart[track] * 8),
            ((ObjSeqState*)seq)->trackRunLength[track] & 0xfff, frame);
    }
    return val;
}

#pragma opt_loop_invariants off
#pragma opt_propagation off
void ObjSeq_RebuildCurveStateToFrame(u8* obj, u8* seqObj, u8* seq, int mode)
{
    struct
    {
        f32 x;
        f32 y;
        f32 z;
    } pos;
    s8 flags;
    f32* posp;
    int out;
    u8* cmd;
    f32 speed;
    u8* model;
    u8* action;
    int found;
    int i;
    int targetFrame;
    u8* activeObj;
    int stop;
    int frame;
    f32 val;
    f32 rate;
    f32 prevX;
    f32 prevZ;
    int opcode;
    u8* entry;

    (void)seqObj;

    if (((ObjSeqState*)seq)->cmds == NULL)
    {
        return;
    }

    flags = 1;
    if (mode != 0)
    {
        flags |= 2;
    }

    model = *(u8**)&((GameObject*)obj)->anim.placementData;
    targetFrame = ((ObjSeqState*)seq)->curFrame;
    lbl_803DD08A = targetFrame;
    ((ObjSeqState*)seq)->cmdCursor = 0;
    ((ObjSeqState*)seq)->retriggerFrame = -0x32;
    ((ObjSeqState*)seq)->unk78 = 0;
    ((ObjSeqState*)seq)->unk7A = 0;
    ((ObjSeqState*)seq)->unk79 = 0;
    ((ObjSeqState*)seq)->targetObj = NULL;
    ((ObjSeqState*)seq)->unk7B = 0;
    ((ObjSeqState*)seq)->fade = 0.0f;
    ((ObjSeqState*)seq)->curFrame = -1;

    found = -1;
    activeObj = obj;
    i = 0;
    while (i < ((ObjSeqState*)seq)->cmdCount && ((ObjSeqState*)seq)->curFrame <= targetFrame)
    {
        cmd = ((ObjSeqState*)seq)->cmds + i * 4;
        opcode = cmd[0];
        switch ((s8)opcode)
        {
        case 3:
            flags = (s8)(flags | 4);
            activeObj = ObjSeq_ToggleCommand3Target(obj, seq, model);
            ((GameObject*)activeObj)->anim.activeMove = -1;
            break;
        case 0:
            ((ObjSeqState*)seq)->curFrame = *(s16*)(cmd + 2);
            break;
        case 9:
            found = ((ObjSeqState*)seq)->curFrame;
            break;
        case 11:
            if (*(s16*)(cmd + 2) > 0)
            {
                i += *(s16*)(cmd + 2);
            }
            break;
        default:
            if ((s8)opcode != 0xf)
            {
                ((ObjSeqState*)seq)->curFrame += cmd[1];
            }
            break;
        }
        i++;
    }

    ((ObjSeqState*)seq)->curFrame = found;
    action = ObjSeq_GetActiveModel(activeObj);
    if (action != NULL)
    {
        val = ObjSeq_SampleTrackCurve(seq, 13, -1);
        prevX = *(f32*)(model + 0x8) + val;
        val = ObjSeq_SampleTrackCurve(seq, 11, -1);
        prevZ = *(f32*)(model + 0x10) + val;
    }

    posp = &pos.x;
    entry = lbl_8039944C;
    while (((ObjSeqState*)seq)->curFrame < targetFrame)
    {
        ((ObjSeqState*)seq)->curFrame += 1;
        frame = ((ObjSeqState*)seq)->curFrame;
        val = ObjSeq_SampleTrackCurve(seq, 13, frame);
        pos.x = *(f32*)(model + 0x8) + val;
        frame = ((ObjSeqState*)seq)->curFrame;
        val = ObjSeq_SampleTrackCurve(seq, 12, frame);
        pos.y = *(f32*)(model + 0xc) + val;
        frame = ((ObjSeqState*)seq)->curFrame;
        val = ObjSeq_SampleTrackCurve(seq, 11, frame);
        pos.z = *(f32*)(model + 0x10) + val;

        if (((ObjSeqState*)seq)->curFrame > 0 && mode != 0)
        {
            if ((s8)((ObjSeqState*)seq)->unk78 == 1 && (s8)((ObjSeqState*)seq)->unk7B == 0 && action != NULL)
            {
                f32 dx = posp[0] - prevX;
                if (ObjAnim_SampleRootCurvePhase(
                    sqrtf(dx * dx + (posp[2] - prevZ) * (posp[2] - prevZ)),
                    (ObjAnimComponent*)activeObj, &speed) == 0)
                {
                    frame = ((ObjSeqState*)seq)->curFrame - 1;
                    val = ObjSeq_SampleTrackCurve(seq, 9, frame);
                    speed = lbl_803DF030 * val;
                }
            }
            else
            {
                frame = ((ObjSeqState*)seq)->curFrame - 1;
                val = ObjSeq_SampleTrackCurve(seq, 9, frame);
                speed = lbl_803DF030 * val;
            }

            if (action != NULL)
            {
                ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)((int)activeObj, speed, lbl_803DEFC8,
                                                                            &((ObjSeqState*)seq)->animEvents);
                if (mode != 0)
                {
                    if (((ObjSeqState*)seq)->fade > lbl_803DEFB0)
                    {
                        if (((ObjSeqState*)seq)->trackRunLength[10] != 0)
                        {
                            frame = ((ObjSeqState*)seq)->curFrame - 1;
                            rate = ObjSeq_SampleTrackCurve(seq, 10, frame);
                        }
                        else
                        {
                            rate = gObjSeqDefaultFadeRate;
                        }
                        if (rate < lbl_803DEFC8)
                        {
                            rate = lbl_803DEFC8;
                        }
                        val = *(f32*)&lbl_803DEFC8 / rate;
                        ((ObjSeqState*)seq)->fade = ((ObjSeqState*)seq)->fade - val;
                        if (((ObjSeqState*)seq)->fade < lbl_803DEFB0)
                        {
                            ((ObjSeqState*)seq)->fade = lbl_803DEFB0;
                        }
                    }
                }
            }
            else
            {
                ((GameObject*)activeObj)->anim.currentMoveProgress += speed;
                while (((GameObject*)activeObj)->anim.currentMoveProgress > lbl_803DEFC8)
                {
                    ((GameObject*)activeObj)->anim.currentMoveProgress =
                        ((GameObject*)activeObj)->anim.currentMoveProgress - lbl_803DEFC8;
                }
                while (((GameObject*)activeObj)->anim.currentMoveProgress < 0.0f)
                {
                    ((GameObject*)activeObj)->anim.currentMoveProgress =
                        ((GameObject*)activeObj)->anim.currentMoveProgress + lbl_803DEFC8;
                }
            }
        }

        prevX = posp[0];
        prevZ = posp[2];

        stop = 0;
        lbl_803DD0C0 = 0;
        while (stop == 0 && ((ObjSeqState*)seq)->cmdCursor < ((ObjSeqState*)seq)->cmdCount)
        {
            cmd = ((ObjSeqState*)seq)->cmds + ((ObjSeqState*)seq)->cmdCursor * 4;
            opcode = (s8)cmd[0];
            if (opcode == 0)
            {
                if (((ObjSeqState*)seq)->curFrame >= *(s16*)(cmd + 2))
                {
                    ((ObjSeqState*)seq)->retriggerFrame = *(s16*)(cmd + 2);
                    ((ObjSeqState*)seq)->cmdCursor += 1;
                }
                else
                {
                    stop = 1;
                }
            }
            else
            {
                if (((ObjSeqState*)seq)->curFrame >= ((ObjSeqState*)seq)->retriggerFrame)
                {
                    if (opcode != 0xf)
                    {
                        ((ObjSeqState*)seq)->retriggerFrame += cmd[1];
                    }
                    ((ObjSeqState*)seq)->cmdCursor += 1;
                    if (ObjSeq_ExecuteActionCommand(obj, action, &cmd, flags, &out) != 0)
                    {
                        return;
                    }
                    activeObj = *(u8**)((GameObject*)obj)->extra;
                    if (activeObj == NULL)
                    {
                        activeObj = obj;
                    }
                    action = ObjSeq_GetActiveModel(activeObj);
                }
                else
                {
                    stop = 1;
                }
            }
        }

        for (i = 0; i < lbl_803DD0C0; i++)
        {
            if (seqDoSubCmd0B(obj, activeObj, seq, *(u8**)(entry + i * 8),
                              *(s16*)(entry + i * 8 + 6), *(s16*)(entry + i * 8 + 4), 1,
                              0) != 0)
            {
                i = lbl_803DD0C0;
            }
            activeObj = *(u8**)((GameObject*)obj)->extra;
            if (activeObj == NULL)
            {
                activeObj = obj;
            }
            action = ObjSeq_GetActiveModel(activeObj);
        }
        lbl_803DD0C0 = 0;
    }
}
#pragma opt_propagation reset
#pragma opt_loop_invariants reset
#pragma reset

#pragma opt_loop_invariants off
void ObjSeq_ApplyFrameCurves(u8* obj, u8* seqObj, u8* seq, int frame)
{
    u8* model;
    u8* walk;
    s16* vec;
    s16* vec2;
    ObjTextureRuntimeSlot* tex1;
    ObjTextureRuntimeSlot* tex2;
    ObjTextureRuntimeSlot* tex5;
    int k;
    int* modelIds;
    int slots;
    int i;
    int vol;
    s16 scroll;
    f32 val;

    model = *(u8**)&((GameObject*)obj)->anim.placementData;
    ((GameObject*)obj)->anim.localPosX = *(f32*)(model + 0x8);
    ((GameObject*)obj)->anim.localPosY = *(f32*)(model + 0xc);
    ((GameObject*)obj)->anim.localPosZ = *(f32*)(model + 0x10);
    ((GameObject*)obj)->anim.rotY = 0;
    ((GameObject*)obj)->anim.rotX = 0;
    ((GameObject*)obj)->anim.rotZ = 0;
    if ((((ObjSeqState*)seq)->flags & 0x20) != 0)
    {
        seqObj[0x36] = 0xff;
    }
    gObjSeqCurvePosOffsetX = lbl_803DEFB0;
    gObjSeqCurvePosOffsetY = lbl_803DEFB0;
    gObjSeqCurvePosOffsetZ = lbl_803DEFB0;

    if (((ObjSeqState*)seq)->animEntries != NULL)
    {
        val = ObjSeq_SampleTrackCurve(seq, 18, frame);
        vol = val;

        for (i = 0; i < 3; i++)
        {
            if (*(s16*)(seq + i * 2 + 0x30) != 0)
            {
                Sfx_IsPlayingFromObject((u32)seqObj, (u16) * (s16*)(seq + i * 2 + 0x38));
            }
        }

        if (vol > 0 && ((ObjSeqState*)seq)->sfxTimer[3] != 0)
        {
            if (Sfx_IsPlayingFromObject((u32)seqObj, (u16)((ObjSeqState*)seq)->sfxId[3]) != 0)
            {
                Sfx_SetObjectSfxVolume((u32)seqObj, (u16)((ObjSeqState*)seq)->sfxId[3], vol,
                                        lbl_803DF038);
            }
        }

        if (((ObjSeqState*)seq)->animEntries == NULL)
            {
                val = lbl_803DEFB0;
            }
            else
            {
                val = lbl_803DEFB0;
                if (((ObjSeqState*)seq)->trackRunLength[7] != 0)
                {
                    val = objCurveInterpolate(
                        (ObjCurveKey*)(((ObjSeqState*)seq)->animEntries + ((ObjSeqState*)seq)->trackAnimStart[7] * 8),
                        ((ObjSeqState*)seq)->trackRunLength[7] & 0xfff, frame);
                }
            }
        ((GameObject*)obj)->anim.rotX = gObjSeqDegreesToAngle * val;

        if (((ObjSeqState*)seq)->animEntries == NULL)
            {
                val = lbl_803DEFB0;
            }
            else
            {
                val = lbl_803DEFB0;
                if (((ObjSeqState*)seq)->trackRunLength[8] != 0)
                {
                    val = objCurveInterpolate(
                        (ObjCurveKey*)(((ObjSeqState*)seq)->animEntries + ((ObjSeqState*)seq)->trackAnimStart[8] * 8),
                        ((ObjSeqState*)seq)->trackRunLength[8] & 0xfff, frame);
                }
            }
        ((GameObject*)obj)->anim.rotY = gObjSeqDegreesToAngle * val;

        if (((ObjSeqState*)seq)->animEntries == NULL)
            {
                val = lbl_803DEFB0;
            }
            else
            {
                val = lbl_803DEFB0;
                if (((ObjSeqState*)seq)->trackRunLength[6] != 0)
                {
                    val = objCurveInterpolate(
                        (ObjCurveKey*)(((ObjSeqState*)seq)->animEntries + ((ObjSeqState*)seq)->trackAnimStart[6] * 8),
                        ((ObjSeqState*)seq)->trackRunLength[6] & 0xfff, frame);
                }
            }
        ((GameObject*)obj)->anim.rotZ = gObjSeqDegreesToAngle * val;

        if (((ObjSeqState*)seq)->animEntries == NULL)
            {
                val = lbl_803DEFB0;
            }
            else
            {
                val = lbl_803DEFB0;
                if (((ObjSeqState*)seq)->trackRunLength[13] != 0)
                {
                    val = objCurveInterpolate(
                        (ObjCurveKey*)(((ObjSeqState*)seq)->animEntries + ((ObjSeqState*)seq)->trackAnimStart[13] * 8),
                        ((ObjSeqState*)seq)->trackRunLength[13] & 0xfff, frame);
                }
            }
        gObjSeqCurvePosOffsetX = val;

        if (((ObjSeqState*)seq)->animEntries == NULL)
            {
                val = lbl_803DEFB0;
            }
            else
            {
                val = lbl_803DEFB0;
                if (((ObjSeqState*)seq)->trackRunLength[12] != 0)
                {
                    val = objCurveInterpolate(
                        (ObjCurveKey*)(((ObjSeqState*)seq)->animEntries + ((ObjSeqState*)seq)->trackAnimStart[12] * 8),
                        ((ObjSeqState*)seq)->trackRunLength[12] & 0xfff, frame);
                }
            }
        gObjSeqCurvePosOffsetY = val;

        if (((ObjSeqState*)seq)->animEntries == NULL)
            {
                val = lbl_803DEFB0;
            }
            else
            {
                val = lbl_803DEFB0;
                if (((ObjSeqState*)seq)->trackRunLength[11] != 0)
                {
                    val = objCurveInterpolate(
                        (ObjCurveKey*)(((ObjSeqState*)seq)->animEntries + ((ObjSeqState*)seq)->trackAnimStart[11] * 8),
                        ((ObjSeqState*)seq)->trackRunLength[11] & 0xfff, frame);
                }
            }
        gObjSeqCurvePosOffsetZ = val;

        gObjSeqLinkedSavedPosX = gObjSeqCurvePosOffsetX;
        gObjSeqLinkedSavedPosY = gObjSeqCurvePosOffsetY;
        gObjSeqLinkedSavedPosZ = gObjSeqCurvePosOffsetZ;
        gObjSeqLinkedSavedPitch = *(s16*)obj;
        gObjSeqLinkedTransformValid = 1;
        ((GameObject*)obj)->anim.localPosX = *(f32*)(model + 0x8) + gObjSeqCurvePosOffsetX;
        ((GameObject*)obj)->anim.localPosY = *(f32*)(model + 0xc) + gObjSeqCurvePosOffsetY;
        ((GameObject*)obj)->anim.localPosZ = *(f32*)(model + 0x10) + gObjSeqCurvePosOffsetZ;

        if (((ObjSeqState*)seq)->trackRunLength[14] != 0)
        {
            if (((ObjSeqState*)seq)->animEntries == NULL)
            {
                val = lbl_803DEFB0;
            }
            else
            {
                val = lbl_803DEFB0;
                if (((ObjSeqState*)seq)->trackRunLength[14] != 0)
                {
                    val = objCurveInterpolate(
                        (ObjCurveKey*)(((ObjSeqState*)seq)->animEntries + ((ObjSeqState*)seq)->trackAnimStart[14] * 8),
                        ((ObjSeqState*)seq)->trackRunLength[14] & 0xfff, frame);
                }
            }
            if ((s8)((ObjSeqState*)seq)->unk7B != 0)
            {
                if (val < lbl_803DF040)
                {
                    val = lbl_803DF040;
                }
                if (val > MTRCallback)
                {
                    val = lbl_803DF044;
                }
                gObjSeqFovOverrideActive = 1;
                gObjSeqFovOverrideValue = val;
            }
            else
            {
                ((ObjSeqState*)seq)->unk10 = val;
            }
        }

        if ((((ObjSeqState*)seq)->flags & 0x20) != 0 && ((ObjSeqState*)seq)->trackRunLength[3] != 0)
        {
            if (((ObjSeqState*)seq)->animEntries == NULL)
            {
                val = lbl_803DEFB0;
            }
            else
            {
                val = lbl_803DEFB0;
                if (((ObjSeqState*)seq)->trackRunLength[3] != 0)
                {
                    val = objCurveInterpolate(
                        (ObjCurveKey*)(((ObjSeqState*)seq)->animEntries + ((ObjSeqState*)seq)->trackAnimStart[3] * 8),
                        ((ObjSeqState*)seq)->trackRunLength[3] & 0xfff, frame);
                }
            }
            if (val < lbl_803DEFB0)
            {
                val = lbl_803DEFB0;
            }
            if (val > DBGCallback)
            {
                val = DBGCallback;
            }
            seqObj[0x36] = val;
        }

        if (((ObjSeqState*)seq)->trackRunLength[4] != 0)
        {
            if (((ObjSeqState*)seq)->animEntries == NULL)
            {
                val = lbl_803DEFB0;
            }
            else
            {
                val = lbl_803DEFB0;
                if (((ObjSeqState*)seq)->trackRunLength[4] != 0)
                {
                    val = objCurveInterpolate(
                        (ObjCurveKey*)(((ObjSeqState*)seq)->animEntries + ((ObjSeqState*)seq)->trackAnimStart[4] * 8),
                        ((ObjSeqState*)seq)->trackRunLength[4] & 0xfff, frame);
                }
            }
            (*gSkyInterface)->setTimeOfDay(lbl_803DEFFC * val);
        }

        if ((((ObjSeqState*)seq)->flags & 0x10) != 0 && ((ObjSeqState*)seq)->trackRunLength[5] != 0)
        {
            if (((ObjSeqState*)seq)->animEntries == NULL)
            {
                val = lbl_803DEFB0;
            }
            else
            {
                val = lbl_803DEFB0;
                if (((ObjSeqState*)seq)->trackRunLength[5] != 0)
                {
                    val = objCurveInterpolate(
                        (ObjCurveKey*)(((ObjSeqState*)seq)->animEntries + ((ObjSeqState*)seq)->trackAnimStart[5] * 8),
                        ((ObjSeqState*)seq)->trackRunLength[5] & 0xfff, frame);
                }
            }
            *(f32*)(seqObj + 8) = val * *(f32*)(*(u8**)(seqObj + 0x50) + 4);
        }

        if ((((ObjSeqState*)seq)->flags & 8) != 0)
        {
            vec = objModelGetVecFn_800395d8(seqObj, 0);
            if (vec != NULL)
            {
                if (((ObjSeqState*)seq)->trackRunLength[1] != 0)
                {
                    if (((ObjSeqState*)seq)->animEntries == NULL)
            {
                val = lbl_803DEFB0;
            }
            else
            {
                val = lbl_803DEFB0;
                if (((ObjSeqState*)seq)->trackRunLength[1] != 0)
                {
                    val = objCurveInterpolate(
                        (ObjCurveKey*)(((ObjSeqState*)seq)->animEntries + ((ObjSeqState*)seq)->trackAnimStart[1] * 8),
                        ((ObjSeqState*)seq)->trackRunLength[1] & 0xfff, frame);
                }
            }
                }
                else
                {
                    val = lbl_803DEFB0;
                }
                vec[0] = (s16)(((ObjSeqState*)seq)->baseRotX + (int)(gObjSeqDegreesToAngle * val));

                if (((ObjSeqState*)seq)->trackRunLength[2] != 0)
                {
                    if (((ObjSeqState*)seq)->animEntries == NULL)
            {
                val = lbl_803DEFB0;
            }
            else
            {
                val = lbl_803DEFB0;
                if (((ObjSeqState*)seq)->trackRunLength[2] != 0)
                {
                    val = objCurveInterpolate(
                        (ObjCurveKey*)(((ObjSeqState*)seq)->animEntries + ((ObjSeqState*)seq)->trackAnimStart[2] * 8),
                        ((ObjSeqState*)seq)->trackRunLength[2] & 0xfff, frame);
                }
            }
                }
                else
                {
                    val = lbl_803DEFB0;
                }
                vec[1] = (s16)(((ObjSeqState*)seq)->baseRotY + (int)(gObjSeqDegreesToAngle * val));

                if (((ObjSeqState*)seq)->trackRunLength[0] != 0)
                {
                    if (((ObjSeqState*)seq)->animEntries == NULL)
            {
                val = lbl_803DEFB0;
            }
            else
            {
                val = lbl_803DEFB0;
                if (((ObjSeqState*)seq)->trackRunLength[0] != 0)
                {
                    val = objCurveInterpolate(
                        (ObjCurveKey*)(((ObjSeqState*)seq)->animEntries + ((ObjSeqState*)seq)->trackAnimStart[0] * 8),
                        ((ObjSeqState*)seq)->trackRunLength[0] & 0xfff, frame);
                }
            }
                }
                else
                {
                    val = lbl_803DEFB0;
                }
                vec[2] = gObjSeqDegreesToAngle * val;

                if ((((ObjSeqState*)seq)->flags & 0x400) != 0)
                {
                    slots = ((SeqByte136*)(seq + 0x136))->modelSlot;
                    modelIds = seqFn_800394a0();
                    if (slots == 0)
                    {
                        slots = 9;
                    }
                    if (vec != NULL)
                    {
                        for (k = 1; k < slots; k++)
                        {
                            vec2 = objModelGetVecFn_800395d8(seqObj, modelIds[k]);
                            if (vec2 != NULL)
                            {
                                vec2[1] = vec[1];
                                vec2[0] = vec[0];
                                vec2[2] = vec[2];
                            }
                        }
                    }
                }
            }
        }

        if ((((ObjSeqState*)seq)->flags & 0x200) != 0)
        {
            vec = objModelGetVecFn_800395d8(seqObj, 1);
            if (vec != NULL)
            {
                if (((ObjSeqState*)seq)->trackRunLength[17] != 0)
                {
                    if (((ObjSeqState*)seq)->animEntries == NULL)
            {
                val = lbl_803DEFB0;
            }
            else
            {
                val = lbl_803DEFB0;
                if (((ObjSeqState*)seq)->trackRunLength[17] != 0)
                {
                    val = objCurveInterpolate(
                        (ObjCurveKey*)(((ObjSeqState*)seq)->animEntries + ((ObjSeqState*)seq)->trackAnimStart[17] * 8),
                        ((ObjSeqState*)seq)->trackRunLength[17] & 0xfff, frame);
                }
            }
                }
                else
                {
                    val = lbl_803DEFB0;
                }
                vec[0] = gObjSeqDegreesToAngle * val;
            }
        }

        if ((((ObjSeqState*)seq)->flags & 0x40) != 0)
        {
            tex1 = objFindTexture(seqObj, 1, 0);
            tex2 = objFindTexture(seqObj, 0, 0);
            if (tex1 != NULL || tex2 != NULL)
            {
                if (((ObjSeqState*)seq)->trackRunLength[15] != 0)
                {
                    if (((ObjSeqState*)seq)->animEntries == NULL)
            {
                val = lbl_803DEFB0;
            }
            else
            {
                val = lbl_803DEFB0;
                if (((ObjSeqState*)seq)->trackRunLength[15] != 0)
                {
                    val = objCurveInterpolate(
                        (ObjCurveKey*)(((ObjSeqState*)seq)->animEntries + ((ObjSeqState*)seq)->trackAnimStart[15] * 8),
                        ((ObjSeqState*)seq)->trackRunLength[15] & 0xfff, frame);
                }
            }
                }
                else
                {
                    val = lbl_803DEFB0;
                }
                scroll = (int)(gObjSeqTexScrollScale * val);
                if (tex1 != NULL)
                {
                    tex1->offsetS = scroll;
                }
                if (tex2 != NULL)
                {
                    tex2->offsetS = (s16)-scroll;
                }

                if (((ObjSeqState*)seq)->trackRunLength[16] != 0)
                {
                    if (((ObjSeqState*)seq)->animEntries == NULL)
            {
                val = lbl_803DEFB0;
            }
            else
            {
                val = lbl_803DEFB0;
                if (((ObjSeqState*)seq)->trackRunLength[16] != 0)
                {
                    val = objCurveInterpolate(
                        (ObjCurveKey*)(((ObjSeqState*)seq)->animEntries + ((ObjSeqState*)seq)->trackAnimStart[16] * 8),
                        ((ObjSeqState*)seq)->trackRunLength[16] & 0xfff, frame);
                }
            }
                }
                else
                {
                    val = lbl_803DEFB0;
                }
                scroll = (s16) - (int)(gObjSeqTexScrollScale * val);
                if (tex1 != NULL)
                {
                    tex1->offsetT = scroll;
                }
                if (tex2 != NULL)
                {
                    tex2->offsetT = scroll;
                }
            }

            tex5 = objFindTexture(seqObj, 5, 0);
            tex2 = objFindTexture(seqObj, 4, 0);
            if (tex5 != NULL)
            {
                tex5->textureId = (s16)((ObjSeqState*)seq)->unk8D << 8;
            }
            if (tex2 != NULL)
            {
                tex2->textureId = (s16)((ObjSeqState*)seq)->unk8E << 8;
            }
        }
    }
    else
    {
        gObjSeqLinkedSavedPosX = lbl_803DEFB0;
        gObjSeqLinkedSavedPosY = lbl_803DEFB0;
        gObjSeqLinkedSavedPosZ = lbl_803DEFB0;
        gObjSeqLinkedSavedPitch = 0;
        gObjSeqLinkedTransformValid = 1;
    }
}
#pragma opt_loop_invariants reset

int ObjSeq_ExecuteActionCommand(u8* obj, u8* action, u8** cmdPtr, int flags, void* out)
{
    u8* base = lbl_80396918;
    s8 noExec;
    s8 doUpdate;
    s8 flag8;
    u8* seq;
    u8* activeObj;
    u8* cmd;
    u8* model;
    u8* animState;
    u8* act2;
    u8* st2;
    u8* entry;
    int opcode;
    int sub;
    int restart;
    int reps;
    int val;
    int slot;
    int minRot;
    f32 blend;
    f32 t;

    (void)out;

    cmd = *cmdPtr;
    {
        s8 f = (s8)flags;
        noExec = (s8)(f & 1);
        doUpdate = (s8)(f & 2);
        flag8 = (s8)(f & 8);
    }
    if (noExec == 0)
    {
        doUpdate = 1;
    }
    seq = ((GameObject*)obj)->extra;
    model = *(u8**)&((GameObject*)obj)->anim.placementData;
    activeObj = *(u8**)seq;
    if (activeObj == NULL)
    {
        activeObj = obj;
    }

    opcode = (s8)cmd[0];
    switch (opcode)
    {
    case 2:
        if (flag8 != 0)
        {
            break;
        }
        ((ObjSeqState*)seq)->moveId = (s16)(*(s16*)(cmd + 2) & 0xfff);
        if (((GameObject*)activeObj)->anim.classId == 1 && ((ObjSeqState*)seq)->moveId < 4)
        {
            ((ObjSeqState*)seq)->moveId += 0x531;
        }
        ((ObjSeqState*)seq)->unk8C = (*(s16*)(cmd + 2) >> 8) & 0xf0;
        if (action == NULL)
        {
            break;
        }
        animState = *(u8**)(action + 0x2c);
        if (((GameObject*)activeObj)->anim.currentMove == ((ObjSeqState*)seq)->moveId)
        {
            if ((s8)animState[0x60] != 0)
            {
                restart = 0;
            }
            else
            {
                restart = 1;
            }
        }
        else
        {
            restart = 1;
        }
        if (doUpdate == 0)
        {
            break;
        }
        if (restart == 0)
        {
            break;
        }
        if ((((ObjSeqState*)seq)->flags & 4) == 0)
        {
            break;
        }
        if (action == NULL)
        {
            break;
        }
        ((ObjAnimState*)animState)->framePhase =
            ((GameObject*)activeObj)->anim.currentMoveProgress *
            ((ObjAnimState*)animState)->frameLength;
        if (((ObjSeqState*)seq)->trackRunLength[10] != 0)
        {
            sub = ((ObjSeqState*)seq)->curFrame - 1;
            if (((ObjSeqState*)seq)->animEntries != NULL && ((ObjSeqState*)seq)->trackRunLength[10] != 0)
            {
                objCurveInterpolate(
                    (ObjCurveKey*)(((ObjSeqState*)seq)->animEntries + ((ObjSeqState*)seq)->trackAnimStart[10] * 8),
                    ((ObjSeqState*)seq)->trackRunLength[10] & 0xfff, sub);
            }
        }
        if (((GameObject*)activeObj)->anim.classId == 1)
        {
            act2 = ObjSeq_GetActiveModel(activeObj);
            animState = *(u8**)(act2 + 0x2c);
            ((ObjAnimState*)animState)->lastBlendMoveIndex = -1;
            *(s16*)&((ObjAnimState*)animState)->eventState = 0;
            *(s16*)&((ObjAnimState*)animState)->prevEventState = 0;
            st2 = *(u8**)(act2 + 0x30);
            if (st2 != NULL)
            {
                *(s16*)(st2 + 0x64) = -1;
                *(s16*)(st2 + 0x58) = 0;
                *(s16*)(st2 + 0x5a) = 0;
                *(s16*)(st2 + 0x5c) = 0;
            }
        }
        ((ObjSeqState*)seq)->fade = lbl_803DEFC8;
        ObjAnim_SetCurrentMove((int)activeObj, ((ObjSeqState*)seq)->moveId,
                               (f32)((ObjSeqState*)seq)->unk8C * lbl_803DF02C, 0);
        break;
    case 1:
        if (flag8 != 0)
        {
            break;
        }
        if ((s8)((ObjSeqState*)seq)->unk7B != 0 && (s8)(base + (s8)((ObjSeqState*)seq)->slot)[0x3a40] != 0)
        {
            ((ObjSeqState*)seq)->unk78 = 0;
            break;
        }
        *(s8*)&((ObjSeqState*)seq)->unk78 = 1 - ((ObjSeqState*)seq)->unk78;
        break;
    case 7:
        *(s8*)&((ObjSeqState*)seq)->unk7A = 1 - ((ObjSeqState*)seq)->unk7A;
        break;
    case 3:
        if (flag8 != 0)
        {
            break;
        }
        if ((flags & 4) != 0)
        {
            break;
        }
        activeObj = ObjSeq_ToggleCommand3Target(obj, seq, model);
        ((GameObject*)activeObj)->anim.activeMove = -1;
        break;
    case 0xb:
        if (doUpdate != 0 && *(s16*)(cmd + 2) > 0 && lbl_803DD0C0 < 0x14)
        {
            entry = base + lbl_803DD0C0 * 8;
            *(u8**)(entry + 0x2b34) = cmd + 4;
            *(s16*)(entry + 0x2b3a) = ((ObjSeqState*)seq)->curFrame;
            reps = *(s16*)(cmd + 2);
            lbl_803DD0C0 = lbl_803DD0C0 + 1;
            *(s16*)(entry + 0x2b38) = reps;
        }
        ((ObjSeqState*)seq)->cmdCursor += *(s16*)(cmd + 2);
        break;
    case 4:
        if (flag8 != 0)
        {
            break;
        }
        if (doUpdate == 0)
        {
            break;
        }
        if (action == NULL)
        {
            break;
        }
        if (*(u8*)(*(u8**)action + 0xf9) == 0)
        {
            break;
        }
        blend = (f32)(int)((*(s16*)(cmd + 2) >> 8) & 0xff);
        if (lbl_803DEFB0 != blend)
        {
            t = lbl_803DEFC8 / blend;
        }
        else
        {
            t = lbl_803DEFC8;
        }
        sub = *(s16*)(cmd + 2) & 0xff;
        if (sub < 0xf)
        {
            ObjModel_SetBlendChannelTargets(action, 2,
                                            *(s8*)(*(u8**)(action + 0x28) + 0x2d), sub - 1, 0,
                                            t);
        }
        else
        {
            ObjModel_SetBlendChannelTargets(action, 0,
                                            *(s8*)(*(u8**)(action + 0x28) + 0xd), sub - 1, 0,
                                            t);
        }
        break;
    case 0xe:
        if (flag8 != 0)
        {
            break;
        }
        (*gGameUIInterface)->showNpcDialogue(*(s16*)(cmd + 2), 0x14, 0x8c, 0);
        break;
    case 0xd:
        if (noExec != 0)
        {
            break;
        }
        if (((*(s16*)(cmd + 2) >> 12) & 0xf) == 8)
        {
            break;
        }
        if ((s8)lbl_803DD113 < 10)
        {
            entry = base + lbl_803DD113 * 8;
            *(u8**)(entry + 0x3ca4) = activeObj;
            *(s8*)(entry + 0x3caa) = (s8)((*(s16*)(cmd + 2) >> 12) & 0xf);
            if ((s8) * (entry + 0x3caa) == 0xb || (s8) * (entry + 0x3caa) == 0xc)
            {
                val = *(s16*)(cmd + 6);
                *(s16*)(base + (s8)(lbl_803DD113++) * 8 + 0x3ca8) = val;
            }
            else
            {
                val = (s16)(*(s16*)(cmd + 2) & 0xfff);
                lbl_803DD113++;
                *(s16*)(entry + 0x3ca8) = val;
            }
        }
        break;
    case 0:
        break;
    }

    if (noExec != 0)
    {
        return 0;
    }

    if ((s8)lbl_803DD112 != 0 || (s8)lbl_803DD111 != 0)
    {
        if ((s8)cmd[0] == 0xd)
        {
            switch ((*(s16*)(cmd + 2) >> 12) & 0xf)
            {
            case 2:
                getEnvfxAct(activeObj, activeObj, *(s16*)(cmd + 2) & 0xfff, 0);
                break;
            case 6:
                warpToMap(*(s16*)(cmd + 2) & 0xfff, 0);
                break;
            case 5:
                break;
            }
        }
        return 0;
    }

    switch ((s8)cmd[0])
    {
    case 6:
        if (flag8 != 0)
        {
            break;
        }
        if (((base + (s8)((ObjSeqState*)seq)->slot)[0x3538] & 0x20) == 0)
        {
            break;
        }
        if ((s8)(base + (s8)((ObjSeqState*)seq)->slot)[0x3c4c] == 3)
        {
            break;
        }
        if (((*(s16*)(cmd + 2) >> 12) & 0xf) != 0xf)
        {
            Sfx_PlayFromObject((u32)obj, (u16)(*(s16*)(cmd + 2) & 0xfff));
        }
        else
        {
            Sfx_PlayFromObject((u32)obj, (u16)(*(s16*)(cmd + 2) & 0xfff));
            ((ObjSeqState*)seq)->sfxTimer[3] = -1;
            ((ObjSeqState*)seq)->sfxId[3] = (s16)(*(s16*)(cmd + 2) & 0xfff);
        }
        break;
    case 0xd:
        switch ((*(s16*)(cmd + 2) >> 12) & 0xf)
        {
        case 0:
            if (((base + (s8)((ObjSeqState*)seq)->slot)[0x3538] & 0x20) != 0)
            {
                val = (*(s16*)(cmd + 2) & 0xfff) + 1;
                if (val == 0xd9 || val == 0x92)
                {
                    Music_Trigger(val, 1);
                }
            }
            break;
        case 2:
            getEnvfxAct(activeObj, activeObj, *(s16*)(cmd + 2) & 0xfff, 0);
            break;
        case 6:
            if (flag8 != 0)
            {
                break;
            }
            warpToMap(*(s16*)(cmd + 2) & 0xfff, 0);
            break;
        case 7:
            break;
        case 8:
            if (flag8 != 0)
            {
                break;
            }
            ((ObjSeqState*)seq)->unk8D = (u8)(*(s16*)(cmd + 2) & 0xfff);
            ((ObjSeqState*)seq)->unk8E = ((ObjSeqState*)seq)->unk8D;
            break;
        case 0xe:
            if (flag8 != 0)
            {
                break;
            }
            ((ObjSeqState*)seq)->unk8D = (u8)(*(s16*)(cmd + 2) & 0xfff);
            break;
        case 0xf:
            if (flag8 != 0)
            {
                break;
            }
            ((ObjSeqState*)seq)->unk8E = (u8)(*(s16*)(cmd + 2) & 0xfff);
            break;
        }
        break;
    case 0xf:
        if (flag8 != 0)
        {
            break;
        }
        if (((base + (s8)((ObjSeqState*)seq)->slot)[0x3538] & 0x20) == 0)
        {
            break;
        }
        if ((s8)(base + (s8)((ObjSeqState*)seq)->slot)[0x3c4c] == 3)
        {
            break;
        }
        if (((*(s16*)(cmd + 2) >> 12) & 0xf) != 0xf)
        {
            minRot = 0x7fff;
            slot = 0;
            for (val = 0; val < 3; val++)
            {
                if (((ObjSeqState*)seq)->sfxTimer[val] < (s16)minRot)
                {
                    slot = val;
                    minRot = ((ObjSeqState*)seq)->sfxTimer[val];
                }
            }
        }
        else
        {
            slot = 3;
        }
        entry = seq + slot * 2;
        if (*(s16*)(entry + 0x30) > 0)
        {
            Sfx_RemoveLoopedObjectSound((u32)obj, (u16) * (s16*)(entry + 0x38));
        }
        cmd[1] = cmd[5];
        cmd[4] = 0x63;
        *(s16*)(entry + 0x30) = *(s16*)(cmd + 6);
        *(s16*)(seq + slot * 2 + 0x38) = (s16)(*(s16*)(cmd + 2) & 0xfff);
        Sfx_AddLoopedObjectSound((u32)obj, (u16) * (s16*)(seq + slot * 2 + 0x38));
        break;
    }
    return 0;
}

#pragma opt_propagation off
#pragma opt_strength_reduction off
#pragma opt_loop_invariants off
int ObjSeq_update(u8* obj, f32 t)
{
    u8* base = lbl_80396918;
    u8* cmd;
    u8* action;
    u8* activeObj;
    f32 scratch[2];
    u8* model;
    u8* seq;
    u8* p;
    u8* entry;
    int runs;
    int step;
    int slot;
    int i;
    int k;
    int targetFrame;
    int stop;
    int opcode;
    int found;
    int pressed;
    int restart;
    int aInt;
    f32 val;
    f32 rate;
    f32 px;
    f32 pz;
    f32 fval;
    f32 prevX;
    f32 prevZ;
    ObjAnimSequenceConditionCallback cb;

    (void)t;

    runs = 0;
    step = lbl_803DB411;
    model = *(u8**)&((GameObject*)obj)->anim.placementData;
    if (model == NULL)
    {
        return 1;
    }

    seq = ((GameObject*)obj)->extra;
    if ((((ObjSeqState*)seq)->unk7F & 2) != 0)
    {
        setJoypadDisabled();
    }
    activeObj = *(u8**)seq;
    gObjSeqStop = 0;
    gObjSeqLinkedTransformValid = 0;
    lbl_803DD112 = 0;
    lbl_803DD111 = 0;

    if (((ObjSeqState*)seq)->unk7E == 3)
    {
        if (((ObjSeqState*)seq)->targetObj != NULL)
        {
            ((GameObject*)activeObj)->pendingParentObj = obj;
            ((GameObject*)activeObj)->objectFlags |= OBJECT_OBJFLAG_SEQ_ATTACHED;
        }
        return 0;
    }

    slot = (s8)((ObjSeqState*)seq)->slot;
    if (base[slot + 0x338c] == 1)
    {
        ((ObjSeqState*)seq)->curFrame = ((s16*)(base + 0x3694))[slot];
        ((ObjSeqState*)seq)->prevFrame = ((ObjSeqState*)seq)->curFrame;
        ObjSeq_RefreshActionCursor(obj, activeObj, seq);
    }
    else
    {
        ((ObjSeqState*)seq)->curFrame = ((f32*)(base + 0x3894))[slot];
    }

    i = 3;
    p = seq + 6;
    while (p -= 2, i-- != 0)
    {
        if (*(s16*)(p + 0x30) > 0)
        {
            *(s16*)(p + 0x30) -= framesThisStep;
            if (*(s16*)(p + 0x30) <= 0)
            {
                *(s16*)(p + 0x30) = 0;
                Sfx_RemoveLoopedObjectSound((u32)obj, (u16) * (s16*)(p + 0x38));
            }
        }
    }
    (base + (s8)((ObjSeqState*)seq)->slot)[0x3cf4] = 0;

    do
    {
        lbl_803DD113 = 0;
        if (((ObjSeqState*)seq)->unk7E == 0)
        {
            obj[0x36] = 0;
            return 1;
        }

        activeObj = obj;
        if (((ObjSeqState*)seq)->targetObj != NULL)
        {
            activeObj = *(u8**)seq;
            ((GameObject*)activeObj)->pendingParentObj = obj;
            ((GameObject*)activeObj)->objectFlags |= OBJECT_OBJFLAG_SEQ_ATTACHED;
        }
        else if ((s8)((ObjSeqState*)seq)->unk7B == 0 && (s8)((ObjSeqState*)seq)->movementState < 4)
        {
            *(s8*)&((ObjSeqState*)seq)->movementState = -1;
        }

        slot = (s8)((ObjSeqState*)seq)->slot;
        if ((s8)base[slot + 0x3c4c] != 0 && (s8)base[slot + 0x39e8] != 0)
        {
            ((ObjSeqState*)seq)->curFrame -= base[slot + 0x39e8];
            if (((ObjSeqState*)seq)->curFrame < 0)
            {
                ((ObjSeqState*)seq)->curFrame = 0;
            }
            ((ObjSeqState*)seq)->prevFrame = (s16)(((ObjSeqState*)seq)->curFrame - 1);
            ObjSeq_RebuildCurveStateToFrame(obj, activeObj, seq, 1);
        }

        lbl_803DD0D8 = 0;
        if (activeObj != obj)
        {
            objCallSeqFn(activeObj, obj, seq, (base + (s8)((ObjSeqState*)seq)->slot)[0x3c4c]);
            lbl_803DD0D8 = 1;
        }

        if ((((ObjSeqState*)seq)->sequenceControlFlags & OBJSEQ_CONTROL_SET_LATCH_B) != 0)
        {
            (base + (s8)((ObjSeqState*)seq)->slot)[0x3b9c] = 1;
        }
        if ((((ObjSeqState*)seq)->sequenceControlFlags & OBJSEQ_CONTROL_CLEAR_LATCH_B) != 0)
        {
            (base + (s8)((ObjSeqState*)seq)->slot)[0x3b9c] = 0;
        }
        if ((((ObjSeqState*)seq)->sequenceControlFlags & OBJSEQ_CONTROL_SET_LATCH_A) != 0)
        {
            (base + (s8)((ObjSeqState*)seq)->slot)[0x3b44] = 1;
        }
        if ((((ObjSeqState*)seq)->sequenceControlFlags & OBJSEQ_CONTROL_CLEAR_LATCH_A) != 0)
        {
            (base + (s8)((ObjSeqState*)seq)->slot)[0x3b44] = 0;
        }
        if ((((ObjSeqState*)seq)->sequenceControlFlags & OBJSEQ_CONTROL_SET_STATE_LATCH) != 0)
        {
            (base + (s8)((ObjSeqState*)seq)->slot)[0x3a40] = 1;
        }
        if ((((ObjSeqState*)seq)->sequenceControlFlags & OBJSEQ_CONTROL_CLEAR_STATE_LATCH) != 0)
        {
            (base + (s8)((ObjSeqState*)seq)->slot)[0x3a40] = 0;
        }

        if (((ObjSeqState*)seq)->unk7E == 2)
        {
            ObjSeq_SetupInitialPlaybackState(obj, &activeObj, seq, model, (void**)&action);
            return 0;
        }

        if ((s8)(base + (s8)((ObjSeqState*)seq)->slot)[0x3c4c] == 1)
        {
            step = 0;
        }
        else if ((s8)(base + (s8)((ObjSeqState*)seq)->slot)[0x3c4c] == 2)
        {
            ((ObjSeqState*)seq)->curFrame = ((ObjSeqState*)seq)->endFrame;
            lbl_803DD112 = 1;
        }
        else if ((s8)(base + (s8)((ObjSeqState*)seq)->slot)[0x3c4c] == 3)
        {
            found = objSeqFindConditional(seq, obj);
            if (found > -1)
            {
                (base + (s8)((ObjSeqState*)seq)->slot)[0x3cf4] = 1;
                ((ObjSeqState*)seq)->curFrame = found;
                ((ObjSeqState*)seq)->prevFrame = ((ObjSeqState*)seq)->curFrame;
            }
        }

        if (((ObjSeqState*)seq)->targetObj != NULL && *(s16*)((u8*)((ObjSeqState*)seq)->targetObj + 0xb4) != -1 &&
            ((base + (s8)((ObjSeqState*)seq)->slot)[0x3538] & 0x10) == 0)
        {
            (*gCameraInterface)->setLetterbox(0x41, 1);
        }

        slot = (s8)((ObjSeqState*)seq)->slot;
        if (base[slot + 0x3590] != 0)
        {
            ((ObjSeqState*)seq)->heading = ((s16*)(base + 0x35e8))[slot];
        }

        if ((s8)((ObjSeqState*)seq)->unk7C != 0)
        {
            if (ObjSeq_EvaluateCondition((s8)((ObjSeqState*)seq)->unk7C - 1, seq, (int)model) == 0)
            {
                ((ObjSeqState*)seq)->unk7C = 0;
            }
            else
            {
                ((f32*)(base + 0x3740))[(s8)((ObjSeqState*)seq)->slot] = (f32)((ObjSeqState*)seq)->curFrame;
                return 0;
            }
        }

        ((ObjSeqState*)seq)->curFrame = (s16)(((ObjSeqState*)seq)->curFrame + step);
        if (((ObjSeqState*)seq)->curFrame > ((ObjSeqState*)seq)->endFrame)
        {
            ((ObjSeqState*)seq)->curFrame = ((ObjSeqState*)seq)->endFrame;
        }
        targetFrame = ((ObjSeqState*)seq)->curFrame;
        ObjSeq_ApplyFrameCurves(obj, activeObj, seq, targetFrame);
        ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.localPosX + *(f32*)(seq + 4);
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY + *(f32*)(seq + 8);
        ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.localPosZ + ((ObjSeqState*)seq)->unk0C;
        ((GameObject*)obj)->anim.rotZ += ((ObjSeqState*)seq)->rotStepZ;
        ((GameObject*)obj)->anim.rotY += ((ObjSeqState*)seq)->rotStepY;
        ((GameObject*)obj)->anim.rotX += ((ObjSeqState*)seq)->rotStepX;

        action = ObjSeq_GetActiveModel(activeObj);
        lbl_803DD0C0 = 0;
        if (action != NULL)
        {
            val = ObjSeq_SampleTrackCurve(seq, 13, ((ObjSeqState*)seq)->prevFrame);
            prevX = *(f32*)(model + 0x8) + val;
            val = ObjSeq_SampleTrackCurve(seq, 11, ((ObjSeqState*)seq)->prevFrame);
            prevZ = *(f32*)(model + 0x10) + val;
        }
        ((ObjSeqState*)seq)->curFrame = ((ObjSeqState*)seq)->prevFrame;

        while (((ObjSeqState*)seq)->curFrame < targetFrame)
        {
            ((ObjSeqState*)seq)->curFrame += 1;
            val = ObjSeq_SampleTrackCurve(seq, 13, ((ObjSeqState*)seq)->curFrame);
            px = *(f32*)(model + 0x8) + val;
            val = ObjSeq_SampleTrackCurve(seq, 11, ((ObjSeqState*)seq)->curFrame);
            pz = *(f32*)(model + 0x10) + val;

            if (((ObjSeqState*)seq)->curFrame > 0 && (((ObjSeqState*)seq)->flags & 4) != 0)
            {
                if ((s8)((ObjSeqState*)seq)->unk78 == 1 && (s8)((ObjSeqState*)seq)->unk7B == 0 && action != NULL)
                {
                    f32 dx = px - prevX;
                    f32 dz = pz - prevZ;
                    if (ObjAnim_SampleRootCurvePhase(
                        sqrtf(dx * dx + dz * dz),
                        (ObjAnimComponent*)activeObj, &scratch[1]) == 0)
                    {
                        i = ((ObjSeqState*)seq)->curFrame - 1;
                        val = ObjSeq_SampleTrackCurve(seq, 9, i);
                        scratch[1] = lbl_803DF030 * val;
                    }
                }
                else
                {
                    i = ((ObjSeqState*)seq)->curFrame - 1;
                    val = ObjSeq_SampleTrackCurve(seq, 9, i);
                    scratch[1] = lbl_803DF030 * val;
                }

                if (action != NULL)
                {
                    ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(
                        (int)activeObj, scratch[1], lbl_803DEFC8,
                        &((ObjSeqState*)seq)->animEvents);
                    if (((ObjSeqState*)seq)->fade > lbl_803DEFB0)
                    {
                        if (((ObjSeqState*)seq)->trackRunLength[10] != 0)
                        {
                            i = ((ObjSeqState*)seq)->curFrame - 1;
                            rate = ObjSeq_SampleTrackCurve(seq, 10, i);
                        }
                        else
                        {
                            rate = gObjSeqDefaultFadeRate;
                        }
                        if (rate < lbl_803DEFC8)
                        {
                            rate = lbl_803DEFC8;
                        }
                        val = *(f32*)&lbl_803DEFC8 / rate;
                        ((ObjSeqState*)seq)->fade = ((ObjSeqState*)seq)->fade - val;
                        if (((ObjSeqState*)seq)->fade < lbl_803DEFB0)
                        {
                            ((ObjSeqState*)seq)->fade = lbl_803DEFB0;
                        }
                    }
                }
                else
                {
                    ((GameObject*)activeObj)->anim.currentMoveProgress += scratch[1];
                    rate = lbl_803DEFC8;
                    while (((GameObject*)activeObj)->anim.currentMoveProgress > rate)
                    {
                        ((GameObject*)activeObj)->anim.currentMoveProgress -= rate;
                    }
                    fval = lbl_803DEFB0;
                    val = lbl_803DEFC8;
                    while (((GameObject*)activeObj)->anim.currentMoveProgress < fval)
                    {
                        ((GameObject*)activeObj)->anim.currentMoveProgress += val;
                    }
                }
            }

            prevX = px;
            prevZ = pz;

            stop = 0;
            while (stop == 0 && ((ObjSeqState*)seq)->cmdCursor < ((ObjSeqState*)seq)->cmdCount)
            {
                cmd = ((ObjSeqState*)seq)->cmds + ((ObjSeqState*)seq)->cmdCursor * 4;
                opcode = (s8)cmd[0];
                if (opcode == 0)
                {
                    if (((ObjSeqState*)seq)->curFrame >= *(s16*)(cmd + 2))
                    {
                        ((ObjSeqState*)seq)->retriggerFrame = *(s16*)(cmd + 2);
                        ((ObjSeqState*)seq)->cmdCursor += 1;
                    }
                    else
                    {
                        stop = 1;
                    }
                }
                else
                {
                    if (((ObjSeqState*)seq)->curFrame >= ((ObjSeqState*)seq)->retriggerFrame)
                    {
                        if (opcode != 0xf)
                        {
                            ((ObjSeqState*)seq)->retriggerFrame += cmd[1];
                        }
                        ((ObjSeqState*)seq)->cmdCursor += 1;
                        if (ObjSeq_ExecuteActionCommand(obj, action, &cmd, 0, 0) != 0)
                        {
                            targetFrame = ((ObjSeqState*)seq)->curFrame;
                        }
                        {
                            u8* t = *(u8**)((GameObject*)obj)->extra;
                            if (t == NULL)
                            {
                                t = obj;
                            }
                            action = ObjSeq_GetActiveModel(t);
                            activeObj = t;
                        }
                    }
                    else
                    {
                        stop = 1;
                    }
                }
            }
        }

        for (k = 0; k < 10; k++)
        {
            u8 op;
            aInt = k + 300;
            op = seq[aInt];
            if (op == 0)
            {
                continue;
            }
            switch (op)
            {
            case 0x12:
                pressed = (getButtonsJustPressed(0) & 0x100) != 0;
                break;
            case 0x13:
                pressed = (getButtonsJustPressed(0) & 0x200) != 0;
                break;
            case 0x14:
            case 0x15:
            case 0x16:
            case 0x17:
            case 0x18:
            case 0x19:
                cb = ((ObjSeqState*)seq)->conditionCallback;
                if (cb != NULL)
                {
                    pressed = cb(((ObjSeqState*)seq)->callbackContext, obj);
                }
                else
                {
                    pressed = 0;
                }
                break;
            case 0x1a:
                pressed = isTalkingToNpc() == 0;
                break;
            default:
                pressed = 0;
                break;
            }
            if (pressed != 0)
            {
                (base + (s8)((ObjSeqState*)seq)->slot)[0x3cf4] = 1;
                ((ObjSeqState*)seq)->curFrame = ((ObjSeqState*)seq)->conditionFrames[k];
                ((ObjSeqState*)seq)->prevFrame = ((ObjSeqState*)seq)->curFrame;
                ((ObjSeqState*)seq)->conditionOpcodes[0] = 0;
                ((ObjSeqState*)seq)->conditionOpcodes[1] = 0;
                ((ObjSeqState*)seq)->conditionOpcodes[2] = 0;
                ((ObjSeqState*)seq)->conditionOpcodes[3] = 0;
                ((ObjSeqState*)seq)->conditionOpcodes[4] = 0;
                ((ObjSeqState*)seq)->conditionOpcodes[5] = 0;
                ((ObjSeqState*)seq)->conditionOpcodes[6] = 0;
                ((ObjSeqState*)seq)->conditionOpcodes[7] = 0;
                ((ObjSeqState*)seq)->conditionOpcodes[8] = 0;
                ((ObjSeqState*)seq)->conditionOpcodes[9] = 0;
                break;
            }
        }

        if ((s8)lbl_803DD0D8 == 0 && activeObj != obj)
        {
            objCallSeqFn(activeObj, obj, seq, (base + (s8)((ObjSeqState*)seq)->slot)[0x3c4c]);
        }

        if (((ObjSeqState*)seq)->sequenceControlFlags != 0)
        {
            restart = 0;
            if ((((ObjSeqState*)seq)->sequenceControlFlags & OBJSEQ_CONTROL_RESTART_AT_SAVED_FRAME) != 0)
            {
                restart = 1;
                ((ObjSeqState*)seq)->sequenceControlFlags =
                    ((ObjSeqState*)seq)->sequenceControlFlags & ~OBJSEQ_CONTROL_RESTART_AT_SAVED_FRAME;
                ((ObjSeqState*)seq)->curFrame = (s16)((ObjSeqState*)seq)->savedFrame;
                ((ObjSeqState*)seq)->prevFrame = ((ObjSeqState*)seq)->curFrame;
            }
            ((ObjSeqState*)seq)->sequenceControlFlags = 0;
            (base + (s8)((ObjSeqState*)seq)->slot)[0x3cf4] = restart;
        }

        ((ObjSeqState*)seq)->eventCount = 0;
        ((ObjSeqState*)seq)->unk80 = 0;
        if (action != NULL && (((ObjSeqState*)seq)->flags & 4) != 0)
        {
            *(u16*)(*(u8**)(action + 0x2c) + 0x58) =
                (u16)(int)(SendMailData * ((ObjSeqState*)seq)->fade);
        }
        ObjSeq_UpdateCurvePosition(obj, seq);
        if ((s8)((ObjSeqState*)seq)->unk7A == 1 &&
            hitDetectFn_800658a4(obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                 ((GameObject*)obj)->anim.localPosZ, scratch, 0) == 0)
        {
            ((GameObject*)obj)->anim.localPosY =
                ((GameObject*)obj)->anim.localPosY +
                ((((GameObject*)obj)->anim.localPosY - scratch[0]) - *(f32*)(model + 0xc));
        }
        *(s16*)obj += ((ObjSeqState*)seq)->heading;
        ObjSeq_ApplyLinkedObjectTransform(obj, activeObj, seq);
        objSeqDoBgCmds0D(seq, activeObj, 0);

        for (k = 0; k < lbl_803DD0C0; k++)
        {
            entry = base + k * 8;
            entry = (u8*)((int)entry + 0x2b34);
            if (seqDoSubCmd0B(obj, activeObj, seq, *(u8**)entry, *(s16*)(entry + 6),
                              *(s16*)(entry + 4), 0, 0) != 0)
            {
                k = lbl_803DD0C0;
            }
            {
                u8* t = *(u8**)((GameObject*)obj)->extra;
                if (t == NULL)
                {
                    t = obj;
                }
                action = ObjSeq_GetActiveModel(t);
                activeObj = t;
            }
        }

        if (gObjSeqStreamStopped != 0)
        {
            gObjSeqStreamStopped = seqStreamFn_8008023c(lbl_803DB720) == 0;
        }
        ((ObjSeqState*)seq)->prevFrame = ((ObjSeqState*)seq)->curFrame;

        if ((s8)gObjSeqStop != 0)
        {
            {
                u8* t = *(u8**)((GameObject*)obj)->extra;
                if (t == NULL)
                {
                    t = obj;
                }
                action = ObjSeq_GetActiveModel(t);
                activeObj = t;
                animatedObjFreeAndSavePlayerPos(obj, t, seq);
            }
        }
        else
        {
            slot = (s8)((ObjSeqState*)seq)->slot;
            if ((s8)base[slot + 0x3cf4] != 0)
            {
                p = base + slot * 2;
                *(s16*)(p + 0x3694) = ((ObjSeqState*)seq)->curFrame;
                (base + (s8)((ObjSeqState*)seq)->slot)[0x338c] = 2;
                ((f32*)(base + 0x3740))[(s8)((ObjSeqState*)seq)->slot] = (f32)((ObjSeqState*)seq)->curFrame;
            }
            slot = (s8)((ObjSeqState*)seq)->slot;
            if (lbl_803DEFF0 == ((f32*)(base + 0x3740))[slot])
            {
                if (lbl_803DB724 == slot)
                {
                    fval = lbl_803DD074;
                    aInt = fval;
                    fval = fval - RecvDataLeng;
                    lbl_803DD074 = fval;
                    if (aInt != (int)fval)
                    {
                        step--;
                        if (fval <= lbl_803DEFB0)
                        {
                            lbl_803DB724 = -1;
                        }
                    }
                }
                ((f32*)(base + 0x3740))[(s8)((ObjSeqState*)seq)->slot] =
                    step + ((f32*)(base + 0x3894))[(s8)((ObjSeqState*)seq)->slot];
            }
        }

        if ((s8)gObjSeqStop != 0)
        {
            break;
        }
        if (((ObjSeqState*)seq)->curFrame >= ((ObjSeqState*)seq)->endFrame)
        {
            break;
        }
    }
    while (runs-- != 0);

    return 0;
}
#pragma opt_loop_invariants reset
#pragma opt_strength_reduction reset
#pragma opt_propagation reset

void ObjSeq_SetupInitialPlaybackState(u8* obj, u8** seqObj, u8* seq, u8* sourceObj, void** outAction)
{
    u8* activeObj;
    s16* modelVec;
    f32 groundY[2];
    long long time;
    u8* historyBase;

    historyBase = lbl_80396918;
    if ((s8)((ObjSeqState*)seq)->unk7B != 0)
    {
        gObjSeqCamModeArgB = 1;
        gObjSeqCamModeArgD = 0x5a;
        gObjSeqCamMode = 0x42;
    }

    ((ObjSeqState*)seq)->curFrame = ((ObjSeqState*)seq)->unk5E;
    ((ObjSeqState*)seq)->prevFrame = -0x3c;
    ObjSeq_ApplyFrameCurves(obj, *seqObj, seq, 0);
    ObjSeq_RebuildCurveStateToFrame(obj, *seqObj, seq, 1);

    activeObj = *(u8**)(((GameObject*)obj)->extra);
    if (activeObj == NULL)
    {
        activeObj = obj;
    }
    *outAction = ObjSeq_GetActiveModel(activeObj);
    *seqObj = activeObj;

    ObjSeq_UpdateCurvePosition(obj, seq);
    if ((s8)((ObjSeqState*)seq)->unk7A == 1 &&
        hitDetectFn_800658a4(obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                             ((GameObject*)obj)->anim.localPosZ, groundY, 0) == 0)
    {
        ((GameObject*)obj)->anim.localPosY =
            ((GameObject*)obj)->anim.localPosY + ((((GameObject*)obj)->anim.localPosY - groundY[0]) - *(f32*)(sourceObj
                + 0xc));
    }

    *(s16*)obj += ((ObjSeqState*)seq)->heading;
    if (*seqObj != obj && (s8)lbl_803DD0D8 == 0)
    {
        objCallSeqFn(*seqObj, obj, seq, ((u8*)(historyBase + 0x3c4c))[(s8)((ObjSeqState*)seq)->slot]);
    }

    ObjSeq_ApplyLinkedObjectTransform(obj, *seqObj, seq);
    ((ObjSeqState*)seq)->unk8D = 0;
    ((ObjSeqState*)seq)->unk8E = 0;
    ((ObjSeqState*)seq)->unk7E = 1;
    ((ObjSeqState*)seq)->prevFrame = ((ObjSeqState*)seq)->curFrame;
    if ((s8)gObjSeqStop != 0)
    {
        animatedObjFreeAndSavePlayerPos(obj, *seqObj, seq);
    }

    ((f32*)(historyBase + 0x3740))[(s8)((ObjSeqState*)seq)->slot] = (f32)((ObjSeqState*)seq)->curFrame;
    ((s16*)(historyBase + 0x2be0))[(s8)((ObjSeqState*)seq)->slot] = ((ObjSeqState*)seq)->curFrame;
    time = OSGetTime();
    ((long long*)(historyBase + 0x2f38))[(s8)((ObjSeqState*)seq)->slot] = time;
    time = OSGetTime();
    ((long long*)(historyBase + 0x2c90))[(s8)((ObjSeqState*)seq)->slot] = time;

    if (*seqObj != NULL)
    {
        objModelClearVecFn_8003aa40(*seqObj);
        if (*(s16*)(*seqObj + 0x44) == 1)
        {
            modelVec = objModelGetVecFn_800395d8(obj, 1);
            if (modelVec != NULL)
            {
                modelVec[0] = 0;
                modelVec[1] = 0;
                modelVec[2] = 0;
            }
        }
    }
}

void ObjSeq_ApplyLinkedObjectTransform(u8* obj, u8* seqObj, u8* seq)
{
    s16 basePitch;
    int baseYaw;
    int baseRoll;
    f32 baseX;
    f32 baseY;
    f32 baseZ;

    if (*(void**)(seqObj + 0x30) == ((GameObject*)obj)->anim.parent || (s8)gObjSeqLinkedTransformValid == 0)
    {
        baseX = ((GameObject*)obj)->anim.localPosX;
        baseY = ((GameObject*)obj)->anim.localPosY;
        baseZ = ((GameObject*)obj)->anim.localPosZ;
        basePitch = ((GameObject*)obj)->anim.rotX;
    }
    else
    {
        baseX = gObjSeqLinkedSavedPosX;
        baseY = gObjSeqLinkedSavedPosY;
        baseZ = gObjSeqLinkedSavedPosZ;
        basePitch = gObjSeqLinkedSavedPitch;
    }

    baseYaw = ((GameObject*)obj)->anim.rotY;
    baseRoll = ((GameObject*)obj)->anim.rotZ;
    if (seqObj != obj)
    {
        if ((((ObjSeqState*)seq)->flags & 1) != 0)
        {
            if ((s8)((ObjSeqState*)seq)->movementState == 2)
            {
                ((GameObject*)seqObj)->anim.localPosX = ((ObjSeqState*)seq)->posOffsetX * ((ObjSeqState*)seq)->posOffsetScale + baseX;
                ((GameObject*)seqObj)->anim.localPosY = ((ObjSeqState*)seq)->posOffsetY * ((ObjSeqState*)seq)->posOffsetScale + baseY;
                ((GameObject*)seqObj)->anim.localPosZ = ((ObjSeqState*)seq)->posOffsetZ * ((ObjSeqState*)seq)->posOffsetScale + baseZ;
            }
            else
            {
                ((GameObject*)seqObj)->anim.localPosX = baseX;
                ((GameObject*)seqObj)->anim.localPosY = baseY;
                ((GameObject*)seqObj)->anim.localPosZ = baseZ;
            }
        }
        if ((((ObjSeqState*)seq)->flags & 2) != 0)
        {
            if ((s8)((ObjSeqState*)seq)->movementState == 2)
            {
                *(s16*)(seqObj + 0) =
                    (s16)((s32)basePitch + (s32)(
                        (f32)((ObjSeqState*)seq)->rotOffsetX * ((ObjSeqState*)seq)->posOffsetScale));
                *(s16*)(seqObj + 2) =
                    (s16)(baseYaw + (s32)((f32)((ObjSeqState*)seq)->rotOffsetY * ((ObjSeqState*)seq)->posOffsetScale));
                *(s16*)(seqObj + 4) =
                    (s16)(baseRoll + (s32)((f32)((ObjSeqState*)seq)->rotOffsetZ * ((ObjSeqState*)seq)->posOffsetScale));
            }
            else
            {
                *(s16*)(seqObj + 0) = basePitch;
                *(s16*)(seqObj + 2) = baseYaw;
                *(s16*)(seqObj + 4) = baseRoll;
            }
        }
    }

    if ((s8)((ObjSeqState*)seq)->unk7B != 0 && (s8)((ObjSeqState*)seq)->unk78 != 0)
    {
        lbl_803DD0B8 = obj;
        lbl_803DD0B6 = framesThisStep;
    }
    Obj_GetWorldPosition(seqObj, &((GameObject*)seqObj)->anim.worldPosX, &((GameObject*)seqObj)->anim.worldPosY,
                         &((GameObject*)seqObj)->anim.worldPosZ);
}

int ObjSeq_EvaluateCondition(int condition, u8* seq, int obj)
{
    f32 sunTime;
    int result;

    result = 0;

    switch (condition)
    {
    case 0:
        if (((ObjSeqState*)seq)->seqCounter <= 0)
        {
            result = 1;
        }
        break;
    case 1:
        if (((ObjSeqState*)seq)->seqCounter > 0)
        {
            result = 1;
        }
        break;
    case 2:
        if ((*gSkyInterface)->getSunPosition(&sunTime) == 0)
        {
            result = 1;
        }
        break;
    case 3:
        if ((*gSkyInterface)->getSunPosition(&sunTime) != 0)
        {
            result = 1;
        }
        break;
    case 4:
        if (gObjSeqBoolFlags[(s8)((ObjSeqState*)seq)->slot] == 0)
        {
            result = 1;
        }
        break;
    case 5:
        if (gObjSeqBoolFlags[(s8)((ObjSeqState*)seq)->slot] == 1)
        {
            result = 1;
        }
        break;
    case 6:
        if (gObjSeqCondFlags[(s8)((ObjSeqState*)seq)->slot] == 0)
        {
            result = 1;
        }
        break;
    case 7:
        if (gObjSeqCondFlags[(s8)((ObjSeqState*)seq)->slot] != 0)
        {
            result = 1;
        }
        break;
    case 8:
        if (seqGlobal1 <= 0)
        {
            result = 1;
        }
        break;
    case 9:
        if (seqGlobal1 > 0)
        {
            result = 1;
        }
        break;
    case 10:
        if (seqGlobal2 <= 0)
        {
            result = 1;
        }
        break;
    case 11:
        if (seqGlobal2 > 0)
        {
            result = 1;
        }
        break;
    case 12:
        if (isGameTimerDisabled() != 0)
        {
            result = 1;
        }
        break;
    case 13:
        if (isGameTimerDisabled() == 0)
        {
            result = 1;
        }
        break;
    case 14:
        if (seqGlobal3 != 0)
        {
            result = 1;
        }
        break;
    case 15:
        if (seqGlobal3 == 0)
        {
            result = 1;
        }
        break;
    case 16:
    case 17:
    default:
        result = 1;
        break;
    }
    return result;
}

void ObjSeq_setXrot(int index, int xrot)
{
    s16 xrot16;

    objSeqXrotChanged[index] = 1;
    xrot16 = xrot;
    objSeqXrotValues[index] = xrot16;
}

int ObjSeq_getBool(int index)
{
    if (index < 0 || index >= 0x55)
    {
        return 0;
    }
    return gObjSeqBoolFlags[index];
}

void ObjSeq_setFlag(int index, int value)
{
    s8 flag;

    if (index < 0 || index >= 0x55)
    {
        return;
    }
    flag = value;
    gObjSeqBoolFlags[index] = flag;
}

void ObjSeq_addBgCmd(int index, int xrot, int yrot)
{
    s8 count;
    s16 shortIndex;
    s16 shortXrot;
    s16 shortYrot;

    if (index < 0 || index >= 0x55)
    {
        return;
    }

    count = gObjSeqBgCmdCount;
    if (count >= 0x1e)
    {
        return;
    }

    shortIndex = index;
    shortYrot = yrot;
    shortXrot = xrot;
    gObjSeqBgCmds[count * 3] = shortIndex;
    gObjSeqBgCmds[count * 3 + 2] = shortYrot;
    gObjSeqBgCmds[gObjSeqBgCmdCount++ * 3 + 1] = shortXrot;
}

void ObjSeq_objLoadAnimData(u8* seq, u8* obj)
{
    u8* base = lbl_80396918;
    s16 size;
    int animId;
    int fileOffset;
    struct
    {
        char tag[4];
        s16 size;
        s16 count;
    } hdr;

    if (*(s16*)(obj + 0x18) == -1)
    {
        return;
    }

    ((ObjSeqState*)seq)->animCount = 0;
    ((ObjSeqState*)seq)->cmdCount = 0;
    animId = *(s16*)(obj + 0x18);
    if ((animId & 0x8000) != 0)
    {
        getTabEntry(lbl_803DD0D4, 0xf, ((animId & 0x7ff0) >> 4) * 2, 8);
        animId = *(s16*)lbl_803DD0D4 + (animId & 0xf);
    }
    else
    {
        animId = animId + 1;
    }

    if (getTableFileEntry(0xe, animId, &fileOffset) == 0)
    {
        fn_80137948(sObjLoadAnimdataNullACRomTabWarning);
        return;
    }

    loadAndDecompressDataFile(0xd, &hdr, fileOffset, 8, 0, 0, 0);
    if (strncmp(hdr.tag, &sSeqAAnimDataTag, 4) != 0 &&
        strncmp(hdr.tag, &sSeqBAnimDataTag, 4) != 0)
    {
        fn_80137948(sObjLoadAnimdataNullACRomTabWarning);
        return;
    }

    size = hdr.size;
    ((ObjSeqState*)seq)->cmdCount = hdr.count;
    if (size == 0)
    {
        fn_80137948(sObjLoadAnimdataNullACRomTabWarning);
        return;
    }

    ((ObjSeqState*)seq)->cmds = mmAlloc(size, 0x11, 0);
    if (((ObjSeqState*)seq)->cmds == NULL)
    {
        fn_80137948(sObjLoadAnimdataNullACRomTabWarning);
        return;
    }

    loadAndDecompressDataFile(0xd, ((ObjSeqState*)seq)->cmds, fileOffset + 8, hdr.size, 0, 0, 0);
    ((ObjSeqState*)seq)->animCount = (s16)(((hdr.size >> 2) - hdr.count) >> 1);
    ((ObjSeqState*)seq)->animEntries = ((ObjSeqState*)seq)->cmds + hdr.count * 4;

    ((ObjSeqState*)seq)->slot = obj[0x1f];
    if ((s8)((ObjSeqState*)seq)->slot > -1)
    {
        (base + (s8)((ObjSeqState*)seq)->slot)[0x3b9c] = 0;
        (base + (s8)((ObjSeqState*)seq)->slot)[0x3b44] = 0;
        (base + (s8)((ObjSeqState*)seq)->slot)[0x3a40] = 0;
    }

    if ((s8)obj[0x22] != 0)
    {
        ((ObjSeqState*)seq)->unk7E = 2;
    }
    else
    {
        ((ObjSeqState*)seq)->unk7E = 0;
    }
    ObjSeq_seqState_init(seq);
}

void ObjSeq_seqState_free(u8* seq)
{
    void* ptr;

    ptr = ((ObjSeqState*)seq)->cmds;
    if (ptr != NULL)
    {
        mm_free(ptr);
        ((ObjSeqState*)seq)->cmds = NULL;
        ((ObjSeqState*)seq)->animEntries = NULL;
    }
    ptr = ((ObjSeqState*)seq)->curveInterp;
    if (ptr != NULL)
    {
        mm_free(ptr);
        ((ObjSeqState*)seq)->curveInterp = NULL;
    }
}

void ObjSeq_seqState_init(u8* seq)
{
    int animIndex;
    int runLength;
    int track;
    int animCount;
    u8* animEntry;
    int commandIndex;
    u8* command;

    for (animCount = 0; animCount < 0x13; animCount++)
    {
        ((ObjSeqState*)seq)->trackRunLength[animCount] = 0;
    }

    track = 0;
    animIndex = 0;
    while (animIndex < ((ObjSeqState*)seq)->animCount)
    {
        runLength = 0;
        commandIndex = ((ObjSeqState*)seq)->animCount;
        while (animIndex + runLength < commandIndex &&
            track == ((s8)(((ObjSeqState*)seq)->animEntries + (animIndex + runLength) * 8)[5] & 0x1f))
        {
            runLength++;
        }
        ((ObjSeqState*)seq)->trackRunLength[track] = runLength;
        ((ObjSeqState*)seq)->trackAnimStart[track] = animIndex;
        track++;
        animIndex += runLength;
    }

    ((ObjSeqState*)seq)->endFrame = 1000;
    commandIndex = 0;
    while (commandIndex < 2 && commandIndex < ((ObjSeqState*)seq)->cmdCount)
    {
        command = ((ObjSeqState*)seq)->cmds + commandIndex * 4;
        if ((s8)command[0] == -1)
        {
            ((ObjSeqState*)seq)->endFrame = *(s16*)(command + 2) + 1;
        }
        commandIndex++;
    }
}

void fn_80081940(void)
{
}

int fn_80081944(void)
{
    return 0;
}

int fn_8008194C(void)
{
    return 0;
}

void fn_80081954(int value)
{
    lbl_803DD084 = value;
}

int fn_8008195C(void)
{
    return lbl_803DD084;
}

int fn_80081964(void)
{
    return 1;
}

typedef struct SeqRunRec
{
    s16 slot;
    s16 flags;
    s16 count;
} SeqRunRec;

typedef struct SeqRunTables
{
    u8 pad0[0x2a80];
    SeqRunRec recs[0x1e];
    u8 pad1[0x800];
    u8 marks[0xb0];
    int handles[0x55];
    u8 cmdFlags[0x58];
    u8 counts[0x58];
    s16 headings[0x55];
    u8 pad2[0xae];
    f32 dists[0x55];
    f32 frames[0x55];
    u8 pad3[0xb0];
    s16 modes[0x55];
} SeqRunTables;

int objRunSeq(int seqIdx, u8* obj, int flags)
{
    u8* base;
    SeqRunTables* st;
    u8* walk2;
    u8* walk;
    int packed;
    u8* mon;
    int i;
    int idx;
    int count;
    int first;
    int bit;
    int objId;
    int slot;
    u8* hdr;
    u8* parent;
    u8* srcSeq;
    u8* setup;
    u8* seq;
    int size;
    s16 heading;
    int camArg;
    u8* player;
    int doCam;
    u8* newObj;
    u8* slotPtr;
    u8* buf;
    u8* blk;
    u8* p;
    s16* mapTbl;
    int j;
    int k;
    int v;
    int seqFlags;
    int found;
    int cur;
    int n;
    s16 val;
    u32 objIdU;
    u32 mapFlags;
    u32 trackId;
    f32 x;
    f32 y;
    f32 z;

    base = lbl_80396918;
    st = (SeqRunTables*)base;
    srcSeq = *(u8**)&((GameObject*)obj)->anim.placementData;
    camArg = 0;
    doCam = 0;
    player = Obj_GetPlayerObject();

    if (seqIdx == -1)
    {
        return -1;
    }
    if (seqIdx < 0 || seqIdx >= ((GameObject*)obj)->anim.modelInstance->sequenceCount)
    {
        return -1;
    }

    for (i = 0x19; i < 0x55; i++)
    {
        p = base + i * 2;
        p = (u8*)((int)p + 0x3a98);
        if (*(s16*)p == 0)
        {
            slot = i;
            *(s16*)p = 1;
            blk = base + i * 0x80;
            for (j = 0; j < 16; j++)
            {
                *(u8**)blk = NULL;
                blk += 8;
            }
            i = 0x56;
        }
    }
    if (i == 0x55)
    {
        return -1;
    }

    mapTbl = ((GameObject*)obj)->anim.modelInstance->sequenceMap;
    if (mapTbl != NULL)
    {
        seqIdx = mapTbl[seqIdx];
    }

    cur = ((GameObject*)obj)->seqIndex;
    if (cur != -1 && lbl_803DD07C == NULL)
    {
        endObjSequence(cur);
    }

    val = seqIdx + 1;
    slotPtr = slot * 2 + 0x3a98 + base;
    *(s16*)slotPtr = val;
    lbl_803DB714 = -1;
    lbl_803DB718 = -1;

    mon = base + 0x3d4c;
    walk = mon;
    n = (s8)lbl_803DD124;
    for (i = 0; i < n; i++)
    {
        if (*(u8**)walk == obj)
        {
            found = 1;
            goto checked;
        }
        walk += 8;
    }
    found = 0;
checked:
    if (found == 0)
    {
        lbl_803DB714 = seqIdx;
    }

    hdr = mmAlloc(0x20, 0x11, 0);
    getTabEntry(hdr, 0x3c, seqIdx * 2, 8);
    first = *(s16*)hdr;
    count = *(s16*)(hdr + 2) - first;
    size = count << 3;
    buf = mmAlloc(size, 0x11, 0);
    getTabEntry(buf, 0x3b, first * 8, size);
    mm_free(hdr);

    if (lbl_803DD07C != NULL)
    {
        obj = lbl_803DD07C;
    }
    ((GameObject*)obj)->seqIndex = slot;
    parent = *(u8**)&((GameObject*)obj)->anim.parent;
    x = ((GameObject*)obj)->anim.localPosX;
    y = ((GameObject*)obj)->anim.localPosY;
    z = ((GameObject*)obj)->anim.localPosZ;
    if (lbl_803DD0B4.useWorldSpace)
    {
        parent = NULL;
        x = ((GameObject*)obj)->anim.worldPosX;
        y = ((GameObject*)obj)->anim.worldPosY;
        z = ((GameObject*)obj)->anim.worldPosZ;
    }
    heading = *(s16*)obj;
    if (lbl_803DD078 != 0)
    {
        x -= ((GameObject*)obj)->anim.rootMotionScale *
            (((GameObject*)obj)->anim.hitboxScale * mathSinf((lbl_803DEFE8 * (f32) * (s16*)obj) / lbl_803DEFEC));
        z -= ((GameObject*)obj)->anim.rootMotionScale *
            (((GameObject*)obj)->anim.hitboxScale * mathCosf((lbl_803DEFE8 * (f32) * (s16*)obj) / lbl_803DEFEC));
    }

    i = 0;
    st->cmdFlags[((GameObject*)obj)->seqIndex] = 0;
    base[((GameObject*)obj)->seqIndex + 0x3334] = 0;
    lbl_8030ECF8[((GameObject*)obj)->seqIndex] = 0;
    st->handles[((GameObject*)obj)->seqIndex] = ((GameObject*)obj)->anim.seqId;

    walk = buf;
    bit = 1;
    for (; i < count; i++)
    {
        if ((flags & (bit << i)) && (*(u16*)(walk + 4) & 0x4000))
        {
            objIdU = *(u16*)(walk + 6);
            if (objIdU == 0x1f || objIdU == 0)
            {
                if (fn_80296C2C(Obj_GetPlayerObject()) == 0)
                {
                    return -1;
                }
            }
        }
        walk += 8;
    }

    idx = 0;
    walk2 = buf;
    packed = ((seqIdx & 0x7ff) << 4) | 0x8000;
    for (; idx < count; idx++)
    {
        if (flags & (1 << idx))
        {
            setup = Obj_AllocObjectSetup(0x28, 6);
            objId = *(u16*)(walk2 + 6);
            if (objId == 0x1f || objId == 0)
            {
                u8* pp = Obj_GetPlayerObject();
                *(u16*)(pp + 0xb0) |= OBJECT_OBJFLAG_SEQ_ATTACHED;
            }
            if (objId == 0xffff)
            {
                *(s16*)setup = 6;
                *(s16*)(setup + 0x1c) = ((GameObject*)obj)->anim.seqId + 4;
                if (((GameObject*)obj)->anim.seqId == 0x443 && objSeqObjs != -1)
                {
                    *(s16*)(setup + 0x1c) = objSeqObjs + 4;
                }
                *(u16*)(walk2 + 4) |= 0x8000;
            }
            else if (objId == 0xfffe)
            {
                *(s16*)setup = 0x1e;
                *(s16*)(setup + 0x1c) = 3;
                curSeqNo = slot;
            }
            else
            {
                if (*(u16*)(walk2 + 4) & 0x4000)
                {
                    *(s16*)setup = 6;
                    if (objId == 0x443)
                    {
                        if (objSeqObjs != -1)
                        {
                            *(s16*)(setup + 0x1c) = objSeqObjs + 4;
                        }
                        else
                        {
                            *(s16*)(setup + 0x1c) = objId + 4;
                        }
                    }
                    else
                    {
                        *(s16*)(setup + 0x1c) = objId + 4;
                    }
                }
                else
                {
                    *(s16*)setup = objId;
                    *(s16*)(setup + 0x1c) = 0;
                }
            }
            if (*(u16*)(walk2 + 4) & 0x8000)
            {
                setup[0x20] = 0;
                setup[0x21] = 0;
            }
            else
            {
                setup[0x20] = 1;
                setup[0x21] = 1;
            }
            if (idx == 0 && (*(u16*)(walk2 + 4) & 0x1000) && player != NULL)
            {
                fn_80297284(player);
            }
            *(s16*)(setup + 0x18) = packed | (idx & 0xf);
            *(s16*)(setup + 0x1a) = -1;
            if (idx != 0)
            {
                if (lbl_803DD0D9 != 0 && *(s16*)setup == 0x1e)
                {
                    ((ObjPlacement*)setup)->posX = x + *(f32*)(base + 0x2bd4);
                    ((ObjPlacement*)setup)->posY = y + *(f32*)(base + 0x2bd8);
                    ((ObjPlacement*)setup)->posZ = z + *(f32*)(base + 0x2bdc);
                    lbl_803DD0D9 = 0;
                }
                else
                {
                    ((ObjPlacement*)setup)->posX = x;
                    ((ObjPlacement*)setup)->posY = y;
                    ((ObjPlacement*)setup)->posZ = z;
                }
            }
            else
            {
                ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
                ((ObjPlacement*)setup)->posY = ((GameObject*)obj)->anim.localPosY;
                ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
            }
            *(s8*)(setup + 0x1f) = slot;
            setup[0x22] = 1;
            setup[0x24] = (*(u16*)(walk2 + 4) & 0xf00) >> 8;
            setup[4] = 2;
            setup[5] = 1;
            if (srcSeq != NULL)
            {
                setup[5] = setup[5] | (srcSeq[5] & 0x18);
            }
            if (*(s16*)setup == 0x1e)
            {
                setup[4] = 1;
            }
            if (*(s16*)setup == 0x443 && objSeqObjs != -1)
            {
                *(s16*)setup = objSeqObjs;
            }
            newObj = Obj_SetupObject(setup, 5, -1, -1, parent);
            ((GameObject*)newObj)->seqIndex = -2;
            seq = ((GameObject*)newObj)->extra;
            ((ObjSeqState*)seq)->heading = heading;
            ((ObjSeqState*)seq)->flags = -1;
            ((ObjSeqState*)seq)->flags = ((ObjSeqState*)seq)->flags & ~0x400;
            ((ObjSeqState*)seq)->conditionOpcodes[0] = 0;
            ((ObjSeqState*)seq)->conditionOpcodes[1] = 0;
            ((ObjSeqState*)seq)->conditionOpcodes[2] = 0;
            ((ObjSeqState*)seq)->conditionOpcodes[3] = 0;
            if (*(u16*)(walk2 + 4) & 1)
            {
                ((ObjSeqState*)seq)->flags = ((ObjSeqState*)seq)->flags & ~1;
            }
            if (*(u16*)(walk2 + 4) & 2)
            {
                ((ObjSeqState*)seq)->flags = ((ObjSeqState*)seq)->flags & ~2;
            }
            if (*(u16*)(walk2 + 4) & 4)
            {
                ((ObjSeqState*)seq)->heading = 0;
            }
            if (*(u16*)(walk2 + 4) & 8)
            {
                ((ObjSeqState*)seq)->flags = ((ObjSeqState*)seq)->flags & ~0x100;
            }
            if (*(u16*)(walk2 + 4) & 0x80)
            {
                ((ObjSeqState*)seq)->unk7F = ((ObjSeqState*)seq)->unk7F | 4;
            }
            if (*(u16*)(walk2 + 4) & 0x40)
            {
                ((ObjSeqState*)seq)->unk7F = ((ObjSeqState*)seq)->unk7F | 2;
            }
            if (*(u16*)(walk2 + 4) & 0x2000)
            {
                if (idx == 0 && player != NULL)
                {
                    fn_8029726C(player);
                }
                if (lbl_803DD064 == 0 || lbl_803DD064 == ((GameObject*)obj)->seqIndex)
                {
                    lbl_803DD064 = ((GameObject*)obj)->seqIndex;
                    curSeqNo = slot;
                }
                ((ObjSeqState*)seq)->movementState = 4;
                if (camArg == 0)
                {
                    camArg = (*(u16*)(walk2 + 4) & 0xf00) >> 8;
                }
                doCam = 1;
            }
            else
            {
                *(s8*)&((ObjSeqState*)seq)->movementState = -1;
            }
            if ((objId == 0x1f || objId == 0) && (((ObjSeqState*)seq)->flags & 1))
            {
                fn_80297254(player);
            }
            ((ObjSeqState*)seq)->targetObjId = *(int*)walk2;
            ((ObjSeqState*)seq)->savedFlags = ((ObjSeqState*)seq)->flags;
            if (idx == 0)
            {
                *(u8*)((u8*)&st->cmdFlags[0] + ((GameObject*)obj)->seqIndex) = *(u16*)(walk2 + 4);
                *(int*)((u8*)&st->handles[0] + ((GameObject*)obj)->seqIndex * 4) =
                    *(int*)(*(u8**)&((GameObject*)newObj)->anim.placementData + 0x14);
                mapFlags = ((ObjAnimComponent*)obj)->modelInstance->flags;
                if ((mapFlags & OBJMODEL_FLAG_SKIP_RESET_UPDATE) && !(mapFlags & 0x8000))
                {
                    parent = obj;
                    z = y = x = lbl_803DEFB0;
                    heading = 0;
                }
            }
        }
        walk2 += 8;
    }

    st->headings[((GameObject*)obj)->seqIndex] = heading;
    j = 0;
    base[((GameObject*)obj)->seqIndex + 0x3590] = 0;
    base[((GameObject*)obj)->seqIndex + 0x338c] = 0;
    n = (s8)lbl_803DD124;
    for (; j < n; j++)
    {
        if (*(u8**)mon == obj)
        {
            seqFlags = *(int*)(base + j * 8 + 0x3d50);
            lbl_803DD124 -= 1;
            p = base + j * 8 + 0x3d4c;
            v = *(int*)(p + 8);
            for (k = j; k < (s8)lbl_803DD124; k++)
            {
                *(int*)p = v;
                *(int*)(p + 4) = v;
                p += 8;
            }
            goto gotFlags;
        }
        mon += 8;
    }
    seqFlags = 0;
gotFlags:
    if (seqFlags != 0)
    {
        st->cmdFlags[((GameObject*)obj)->seqIndex] |= 0x10;
    }
    else
    {
        gObjSeqStreamStopped = 0;
        trackId = (u32)(*(s16*)slotPtr - 1) & 0x3fff;
        gObjSeqCurrentTrackId = trackId;
        if (AudioStream_Play(trackId, streamCb_80080384) == 0)
        {
            if (lbl_803DB714 != -1)
            {
                gameTextLoadTaskText(lbl_803DB714);
                lbl_803DB714 = -1;
            }
        }
        else
        {
            lbl_803DB720 = slot;
            lbl_803DB71C = lbl_803DB714;
            lbl_803DB724 = -1;
            lbl_803DD074 = lbl_803DEFB0;
            lbl_803DB728 = -1;
        }
    }

    st->dists[((GameObject*)obj)->seqIndex] = seqFlags;
    st->frames[((GameObject*)obj)->seqIndex] = seqFlags;

    if (slot >= 0 && slot < 0x55)
    {
        if (gObjSeqBgCmdCount < 0x1e)
        {
            st->recs[gObjSeqBgCmdCount].slot = slot;
            st->recs[gObjSeqBgCmdCount].count = count;
            st->recs[gObjSeqBgCmdCount++].flags = seqFlags;
        }
    }

    if (doCam != 0)
    {
        cameraFocusNpc(camArg, obj);
    }
    mm_free(buf);
    lbl_803DD078 = 0;
    lbl_803DD0B4.useWorldSpace = 0;
    return slot;
}

int ObjSeq_ResolveAndAssignTargetObject(u8* obj)
{
    int objectCount;
    void* unused;
    void** objects;
    u8* seqObj;
    u8* model;
    u8* found;
    int j;
    u8* entry;
    u8* slotBase;
    u8* candidate;
    int objType;
    int i;
    u8* linked;
    f32 bestDist;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 distSq;

    objects = ObjList_GetObjects(&unused, &objectCount);
    seqObj = ((GameObject*)obj)->extra;
    model = *(u8**)&((GameObject*)obj)->anim.placementData;
    if (((GameObject*)obj)->anim.classId == 0x11)
    {
        ((ObjSeqState*)seqObj)->targetObj = NULL;
        return -1;
    }

    switch (*(s16*)(model + 0x1c))
    {
    case 0:
        ((ObjSeqState*)seqObj)->targetObj = NULL;
        break;
    case 1:
        ((ObjSeqState*)seqObj)->targetObj = Obj_GetPlayerObject();
        break;
    case 2:
        ((ObjSeqState*)seqObj)->targetObj = getTrickyObject();
        break;
    case 3:
        ((ObjSeqState*)seqObj)->targetObj = NULL;
        *(s8*)&((ObjSeqState*)seqObj)->unk7B = (s8)(*(s16*)(model + 0x1c) - 2);
        if (lbl_803DD064 != 0)
        {
            lbl_803DD064 = 0;
        }
        if ((lbl_80399E50[(s8)seqObj[0x57]] & 0x10) == 0)
        {
            (*gCameraInterface)->setLetterbox(0x41, 1);
        }
        break;
    default:
        ((ObjSeqState*)seqObj)->targetObj = NULL;
        objType = *(s16*)(model + 0x1c) - 4;
        if (objType == 0x1f || objType == 0)
        {
            ((ObjSeqState*)seqObj)->targetObj = Obj_GetPlayerObject();
        }
        else if (((ObjSeqState*)seqObj)->targetObjId != 0)
        {
            ((ObjSeqState*)seqObj)->targetObj = ObjList_FindObjectById(((ObjSeqState*)seqObj)->targetObjId);
        }
        else
        {
            bestDist = lbl_803DEFF0;
            for (i = 0; i < objectCount; i++)
            {
                candidate = objects[i];
                j = 0;
                slotBase = lbl_80396918 + (s8)seqObj[0x57] * 0x80;
                entry = slotBase;
                for (; j < 16; j++)
                {
                    if (*(u8**)entry == candidate)
                    {
                        linked = *(u8**)(slotBase + j * 8 + 4);
                        goto check;
                    }
                    entry += 8;
                }
                linked = NULL;
            check:
                if (linked == obj)
                {
                    ((ObjSeqState*)seqObj)->targetObj = candidate;
                    break;
                }
                if (linked == NULL)
                {
                    if (((GameObject*)candidate)->anim.seqId == objType)
                    {
                        dx = ((GameObject*)obj)->anim.localPosX - ((GameObject*)candidate)->anim.localPosX;
                        dy = ((GameObject*)obj)->anim.localPosY - ((GameObject*)candidate)->anim.localPosY;
                        dz = ((GameObject*)obj)->anim.localPosZ - ((GameObject*)candidate)->anim.localPosZ;
                        distSq = dx * dx + dy * dy + dz * dz;
                        if (bestDist < lbl_803DEFB0 || distSq < bestDist)
                        {
                            bestDist = distSq;
                            ((ObjSeqState*)seqObj)->targetObj = candidate;
                        }
                    }
                }
            }
        }
        break;
    }

    found = *(u8**)seqObj;
    if (found != NULL)
    {
        if ((s8)seqObj[0x57] < 0x19)
        {
            if (*(s16*)(found + 0xb4) != -1)
            {
                endObjSequence(*(s16*)(found + 0xb4));
            }
        }
        return *(s16*)(*(u8**)seqObj + 0x48);
    }
    return -1;
}

void* ObjSeq_FindTargetObject(u8* obj)
{
    int objectCount;
    void* unused;
    void** objects;
    int targetId;
    int objectType;
    u8* candidate;
    void* bestObj;
    int i;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 distSq;
    f32 bestDistSq;

    targetId = *(int*)(*(u8**)&((GameObject*)obj)->extra + 0x10c);
    if (targetId != 0)
    {
        return ObjList_FindObjectById(targetId);
    }

    objects = ObjList_GetObjects(&unused, &objectCount);
    objectType = *(s16*)(*(u8**)&((GameObject*)obj)->anim.placementData + 0x1c) - 4;
    if (objectType == 0x1f || objectType == 0)
    {
        return Obj_GetPlayerObject();
    }
    if (objectType == 0x24 || objectType == 0x25)
    {
        return getTrickyObject();
    }

    {
    bestDistSq = lbl_803DEFF0;
    bestObj = NULL;
    for (i = 0; i < objectCount; i++)
    {
        candidate = objects[i];
        if (((GameObject*)candidate)->anim.seqId == objectType)
        {
            dx = ((GameObject*)obj)->anim.localPosX - ((GameObject*)candidate)->anim.localPosX;
            dy = ((GameObject*)obj)->anim.localPosY - ((GameObject*)candidate)->anim.localPosY;
            dz = ((GameObject*)obj)->anim.localPosZ - ((GameObject*)candidate)->anim.localPosZ;
            distSq = dx * dx + dy * dy + dz * dz;
            if (bestDistSq < 0.0f || distSq < bestDistSq)
            {
                bestDistSq = distSq;
                bestObj = candidate;
            }
        }
    }
    }
    return bestObj;
}

void ObjSeq_RefreshActionCursor(void* obj, void* seqFile, u8* seq)
{
    int actionIndex;
    u8* command;
    u8 opcode;
    int stop;

    if (((ObjSeqState*)seq)->cmds == NULL)
    {
        return;
    }

    ((ObjSeqState*)seq)->retriggerFrame = -1;
    ((ObjSeqState*)seq)->cmdCursor = 0;
    ((ObjSeqState*)seq)->fade = lbl_803DEFB0;
    stop = 0;
    while (stop == 0 && ((ObjSeqState*)seq)->cmdCursor < ((ObjSeqState*)seq)->cmdCount)
    {
        actionIndex = ((ObjSeqState*)seq)->cmdCursor;
        command = ((ObjSeqState*)seq)->cmds + actionIndex * 4;
        opcode = command[0];
        if ((s8)opcode == 0)
        {
            if (((ObjSeqState*)seq)->curFrame >= *(s16*)(command + 2))
            {
                ((ObjSeqState*)seq)->retriggerFrame = *(s16*)(command + 2);
                ((ObjSeqState*)seq)->cmdCursor++;
            }
            else
            {
                stop = 1;
            }
        }
        else if ((s8)opcode == 0xb && *(s16*)(command + 2) > 0)
        {
            if (((ObjSeqState*)seq)->curFrame >= ((ObjSeqState*)seq)->retriggerFrame)
            {
                ((ObjSeqState*)seq)->retriggerFrame += command[1];
                ((ObjSeqState*)seq)->cmdCursor = (s16)(((ObjSeqState*)seq)->cmdCursor + (*(s16*)(command + 2) + 1));
            }
            else
            {
                stop = 1;
            }
        }
        else if (((ObjSeqState*)seq)->curFrame >= ((ObjSeqState*)seq)->retriggerFrame)
        {
            if ((s8)command[0] != 0xf)
            {
                ((ObjSeqState*)seq)->retriggerFrame += command[1];
            }
            ((ObjSeqState*)seq)->cmdCursor++;
        }
        else
        {
            stop = 1;
        }
    }
}

#pragma ppc_unroll_speculative off
#pragma optimization_level 3
#pragma opt_propagation off
void objSeq_onMapSetup(void)
{
    u8* base = lbl_80396918;
    u8* flagsB;
    u8* flagsA;
    s16* modes;
    u8* actions;
    u8* results;
    u8* states;
    u8* pending;
    f32* frames;
    f32* dists;
    u8* counts;
    int* handles;
    u8* marks;
    int* handles2;
    u8* marks2;
    int i = 0;

    flagsB = base + 0x3b9c;
    flagsA = base + 0x3b44;
    modes = (s16*)(base + 0x3a98);
    actions = base + 0x3c4c;
    results = base + 0x3bf4;
    states = base + 0x3a40;
    pending = base + 0x39e8;
    frames = (f32*)(base + 0x3894);
    dists = (f32*)(base + 0x3740);
    counts = base + 0x3590;
    handles = (int*)(base + 0x33e4);
    marks = base + 0x338c;

    {
        for (; i < 0x50; i += 8)
        {
            flagsB[0] = 0;
            flagsA[0] = 0;
            modes[0] = 0;
            actions[0] = 0;
            results[0] = 0;
            states[0] = 0;
            pending[0] = 0;
            frames[0] = lbl_803DEFB0;
            dists[0] = lbl_803DEFF0;
            counts[0] = 0;
            handles[0] = 0;
            marks[0] = 0;
            flagsB[1] = 0;
            flagsA[1] = 0;
            modes[1] = 0;
            actions[1] = 0;
            results[1] = 0;
            states[1] = 0;
            pending[1] = 0;
            frames[1] = lbl_803DEFB0;
            dists[1] = lbl_803DEFF0;
            counts[1] = 0;
            handles[1] = 0;
            marks[1] = 0;
            flagsB[2] = 0;
            flagsA[2] = 0;
            modes[2] = 0;
            actions[2] = 0;
            results[2] = 0;
            states[2] = 0;
            pending[2] = 0;
            frames[2] = lbl_803DEFB0;
            dists[2] = lbl_803DEFF0;
            counts[2] = 0;
            handles[2] = 0;
            marks[2] = 0;
            flagsB[3] = 0;
            flagsA[3] = 0;
            modes[3] = 0;
            actions[3] = 0;
            results[3] = 0;
            states[3] = 0;
            pending[3] = 0;
            frames[3] = lbl_803DEFB0;
            dists[3] = lbl_803DEFF0;
            counts[3] = 0;
            handles[3] = 0;
            marks[3] = 0;
            flagsB[4] = 0;
            flagsA[4] = 0;
            modes[4] = 0;
            actions[4] = 0;
            results[4] = 0;
            states[4] = 0;
            pending[4] = 0;
            frames[4] = lbl_803DEFB0;
            dists[4] = lbl_803DEFF0;
            counts[4] = 0;
            handles[4] = 0;
            marks[4] = 0;
            flagsB[5] = 0;
            flagsA[5] = 0;
            modes[5] = 0;
            actions[5] = 0;
            results[5] = 0;
            states[5] = 0;
            pending[5] = 0;
            frames[5] = lbl_803DEFB0;
            dists[5] = lbl_803DEFF0;
            counts[5] = 0;
            handles[5] = 0;
            marks[5] = 0;
            flagsB[6] = 0;
            flagsA[6] = 0;
            modes[6] = 0;
            actions[6] = 0;
            results[6] = 0;
            states[6] = 0;
            pending[6] = 0;
            frames[6] = lbl_803DEFB0;
            dists[6] = lbl_803DEFF0;
            counts[6] = 0;
            handles[6] = 0;
            marks[6] = 0;
            flagsB[7] = 0;
            flagsA[7] = 0;
            modes[7] = 0;
            actions[7] = 0;
            results[7] = 0;
            states[7] = 0;
            pending[7] = 0;
            frames[7] = lbl_803DEFB0;
            dists[7] = lbl_803DEFF0;
            counts[7] = 0;
            handles[7] = 0;
            marks[7] = 0;
            flagsB += 8;
            flagsA += 8;
            modes += 8;
            actions += 8;
            results += 8;
            states += 8;
            pending += 8;
            frames += 8;
            dists += 8;
            counts += 8;
            handles += 8;
            marks += 8;
        }
    }

    {
        flagsB = base + i;
        modes = (s16*)(base + 0x3a98) + i;
        frames = (f32*)((int)base + (i << 2));
        handles2 = (int*)(frames + 3321);
        marks2 = flagsB + 0x338c;
        for (; i < 0x55; i++)
        {
            frames = (f32*)(handles2 + 300);
            dists = (f32*)(handles2 + 215);
            flagsA = marks2 + 0x7b8;
            flagsB = marks2 + 0x810;
            actions = marks2 + 0x8c0;
            results = marks2 + 0x868;
            states = marks2 + 0x6b4;
            pending = marks2 + 0x65c;
            counts = marks2 + 0x204;
            flagsA[0] = 0;
            flagsB[0] = 0;
            modes[0] = 0;
            actions[0] = 0;
            results[0] = 0;
            states[0] = 0;
            pending[0] = 0;
            frames[0] = lbl_803DEFB0;
            dists[0] = lbl_803DEFF0;
            counts[0] = 0;
            handles2[0] = 0;
            marks2[0] = 0;
            modes++;
            handles2++;
            marks2++;
        }
    }

    lbl_803DD124 = 0;
    gObjSeqCamMode = 0;
    gObjSeqCameraActive = 0;
    lbl_803DD0DC = lbl_803DEFB0;
    lbl_803DD0B8 = NULL;
    lbl_803DD0F8 = 0;
    gObjSeqBgCmdCount = 0;
}
#pragma opt_propagation reset
#pragma optimization_level reset
#pragma ppc_unroll_speculative on

void ObjSeq_release(void)
{
    mm_free(lbl_803DD0D4);
}

void ObjSeq_initialise(void)
{
    lbl_803DD0D4 = mmAlloc(0x10, 0x11, 0);
    objSeq_onMapSetup();
    gObjSeqCamModeArgB = 1;
    gObjSeqCamModeArgD = 0x5a;
    gObjSeqCamMode = 0x42;
    objSeqInitFn_80080078(gObjSeqStreamTableA, 5);
}

int ObjSeq_takeXrotChanged(int index)
{
    int changed;

    changed = objSeqXrotChanged[index];
    objSeqXrotChanged[index] = 0;
    return changed;
}

void fn_80088730(u8* out)
{
    u8* src;

    out[0] = lbl_803DB748;
    src = &lbl_803DB748;
    out[1] = src[1];
    out[2] = src[2];
    out[3] = src[3];
}

void RomCurveInterp_BuildSegmentTimeTable(RomCurveInterpState* out, RomCurveNode* curve, RomCurveNode* next, f32 t,
                                          int flag)
{
    f32 curveScale;
    f32 nextScale;
    f32 xPoints[4];
    f32 yPoints[4];
    f32 zPoints[4];
    f32 xSamples[9];
    f32 ySamples[9];
    f32 zSamples[9];
    f32* times;
    f32 dx;
    f32 dy;
    f32 dz;
    int i;

    curveScale = ROM_CURVE_NODE_SCALE(curve);
    nextScale = ROM_CURVE_NODE_SCALE(next);

    xPoints[0] = curve->x;
    xPoints[2] = curveScale * mathSinf(ROM_CURVE_NODE_ANGLE(curve->yaw));
    xPoints[1] = next->x;
    xPoints[3] = nextScale * mathSinf(ROM_CURVE_NODE_ANGLE(next->yaw));

    yPoints[0] = curve->y;
    yPoints[2] = curveScale * mathSinf(ROM_CURVE_NODE_ANGLE(curve->pitch));
    yPoints[1] = next->y;
    yPoints[3] = nextScale * mathSinf(ROM_CURVE_NODE_ANGLE(next->pitch));

    zPoints[0] = curve->z;
    zPoints[2] = curveScale * mathCosf(ROM_CURVE_NODE_ANGLE(curve->yaw));
    zPoints[1] = next->z;
    zPoints[3] = nextScale * mathCosf(ROM_CURVE_NODE_ANGLE(next->yaw));

    Curve_SampleSegmentPoints(xPoints, yPoints, zPoints, xSamples, ySamples, zSamples, 8,
                              Curve_BuildHermiteCoeffs);

    times = (f32*)out;
    times[2] = lbl_803DEFB0;
    for (i = 0; i < 8; i++)
    {
        dx = xSamples[i + 1] - xSamples[i];
        dy = ySamples[i + 1] - ySamples[i];
        dz = zSamples[i + 1] - zSamples[i];
        times[i + 3] = times[i + 2] + sqrtf(dx * dx + dy * dy + dz * dz);
    }
    if ((s8)flag == 1)
    {
        t -= out->toTime;
    }
    for (i = 0; i <= 8; i++)
    {
        times[i + 2] += t;
    }
}

void RomCurveInterp_UpdateSegmentWindow(RomCurveInterpState* state, f32 t)
{
    RomCurveNode* node;
    RomCurveNode* prev;
    int found;
    int i;
    int mask;
    int val;
    f32 thr;

    node = NULL;
    if (t < state->fromTime)
    {
        node = (RomCurveNode*)(*gRomCurveInterface)->getById(state->fromNodeId);
    }
    if (node != NULL)
    {
        while (t < (thr = state->fromTime))
        {
            mask = 1;
            for (i = 0; i < 4; i++)
            {
                val = node->links[i];
                if (val > -1 && (node->directionMask & mask) != 0)
                {
                    found = val;
                    i = 5;
                }
                mask <<= 1;
            }
            if (i != 6)
            {
                state->toTime = thr;
                state->toNodeId = state->fromNodeId;
                state->fromNodeId = -1;
                return;
            }
            state->toNodeId = state->fromNodeId;
            state->fromNodeId = found;
            prev = node;
            node = (RomCurveNode*)(*gRomCurveInterface)->getById(state->fromNodeId);
            RomCurveInterp_BuildSegmentTimeTable(state, node, prev, state->fromTime, 1);
        }
    }
    node = (RomCurveNode*)(*gRomCurveInterface)->getById(state->toNodeId);
    if (node == NULL)
    {
        return;
    }
    while (t >= (thr = state->toTime))
    {
        mask = 1;
        for (i = 0; i < 4; i++)
        {
            val = node->links[i];
            if (val > -1 && (node->directionMask & mask) == 0)
            {
                found = val;
                i = 5;
            }
            mask <<= 1;
        }
        if (i != 6)
        {
            state->fromTime = thr;
            state->fromNodeId = state->toNodeId;
            state->toNodeId = -1;
            return;
        }
        state->fromNodeId = state->toNodeId;
        state->toNodeId = found;
        prev = node;
        node = (RomCurveNode*)(*gRomCurveInterface)->getById(state->toNodeId);
        RomCurveInterp_BuildSegmentTimeTable(state, prev, node, state->toTime, 0);
    }
}

void RomCurveInterp_InitFromNode(RomCurveInterpState* out, int id)
{
    RomCurveNode* curve;
    int i;
    int mask;
    int found;
    int val;

    out->fromNodeId = id;
    out->toNodeId = -1;
    curve = (RomCurveNode*)(*gRomCurveInterface)->getById(out->fromNodeId);
    mask = 1;
    for (i = 0; i < 4; i++)
    {
        val = curve->links[i];
        if (val > -1 && (curve->directionMask & mask) == 0)
        {
            found = val;
            i = 5;
        }
        mask <<= 1;
    }
    if (i != 6)
    {
        out->fromNodeId = -1;
    }
    else
    {
        out->toNodeId = found;
        RomCurveInterp_BuildSegmentTimeTable(
            out, curve, (RomCurveNode*)(*gRomCurveInterface)->getById(out->toNodeId),
            lbl_803DEFB0, 0);
    }
}

int RomCurveInterp_EvaluateOffsetPosition(RomCurveInterpState* state, f32* offset, f32* outPos, s16* outAngle,
                                          int ignoreY)
{
    RomCurveNode* from;
    RomCurveNode* to;
    f32 segmentT;
    f32 t;
    f32 fromScale;
    f32 toScale;
    f32 xPoints[4];
    f32 yPoints[4];
    f32 zPoints[4];
    f32 xTangent;
    f32 yTangent;
    f32 zTangent;
    f32 length;
    f32 scale;
    f32 angle;
    int segment;
    int i;

    t = offset[2];
    RomCurveInterp_UpdateSegmentWindow(state, t);
    from = (RomCurveNode*)(*gRomCurveInterface)->getById(state->fromNodeId);
    if (from != NULL && state->toNodeId > -1)
    {
        to = (RomCurveNode*)(*gRomCurveInterface)->getById(state->toNodeId);
        i = 0;
        while (i <= 8 && t >= *(f32*)((u8*)state + (i << 2) + 8))
        {
            i++;
        }
        segment = i - 1;
        {
            f32* times = (f32*)state;
            segmentT = segment + (t - times[segment + 2]) /
                (times[segment + 3] - times[segment + 2]);
        }
        segmentT = segmentT * lbl_803DF01C;

        fromScale = ROM_CURVE_NODE_SCALE(from);
        toScale = ROM_CURVE_NODE_SCALE(to);

        xPoints[0] = from->x;
        xPoints[2] = fromScale * mathSinf(ROM_CURVE_NODE_ANGLE(from->yaw));
        xPoints[1] = to->x;
        xPoints[3] = toScale * mathSinf(ROM_CURVE_NODE_ANGLE(to->yaw));

        yPoints[0] = from->y;
        yPoints[2] = fromScale * mathSinf(ROM_CURVE_NODE_ANGLE(from->pitch));
        yPoints[1] = to->y;
        yPoints[3] = toScale * mathSinf(ROM_CURVE_NODE_ANGLE(to->pitch));

        zPoints[0] = from->z;
        zPoints[2] = fromScale * mathCosf(ROM_CURVE_NODE_ANGLE(from->yaw));
        zPoints[1] = to->z;
        zPoints[3] = toScale * mathCosf(ROM_CURVE_NODE_ANGLE(to->yaw));

        {
            extern f32 Curve_EvalHermite(f32* values, f32 t, f32* outTangent);
            outPos[0] = Curve_EvalHermite(xPoints, segmentT, &xTangent);
            if ((s8)ignoreY == 0)
            {
                outPos[1] = Curve_EvalHermite(yPoints, segmentT, &yTangent);
            }
            outPos[2] = Curve_EvalHermite(zPoints, segmentT, &zTangent);
        }

        length = sqrtf(xTangent * xTangent + zTangent * zTangent);
        if (length > lbl_803DF020)
        {
            scale = offset[0] / length;
            *outAngle = (s16)(getAngle(xTangent, zTangent) + 0x8000);
            xTangent *= scale;
            zTangent *= scale;
            outPos[0] += zTangent;
            outPos[2] -= xTangent;
            if ((s8)ignoreY == 0)
            {
                outPos[1] += offset[1];
            }
        }
    }
    else
    {
        if (from == NULL)
        {
            from = (RomCurveNode*)(*gRomCurveInterface)->getById(state->toNodeId);
        }
        if (from != NULL)
        {
            outPos[0] = from->x;
            if ((s8)ignoreY == 0)
            {
                outPos[1] = from->y + offset[1];
            }
            outPos[2] = from->z;
            outPos[0] += offset[0] * mathCosf(ROM_CURVE_NODE_ANGLE(from->yaw));
            outPos[2] += offset[0] * mathSinf(ROM_CURVE_NODE_ANGLE(from->yaw));
            *outAngle = (s16)(((s32)from->yaw << 8) + 0x8000);
        }
        else
        {
            return 0;
        }
    }
    return 1;
}

void ObjSeq_UpdateCurvePosition(u8* obj, u8* seq)
{
    u8* base;
    RomCurveNode* node;
    f32 outPos[3];
    f32 offset[3];
    f32 dx;
    f32 dy;
    f32 dz;
    f32 angleSin;
    f32 angleCos;
    f32 x;
    f32 y;
    f32 z;

    base = *(u8**)&((GameObject*)obj)->anim.placementData;
    if (base == NULL)
    {
        return;
    }

    if (((ObjSeqState*)seq)->curveId < 0)
    {
        dx = ((GameObject*)obj)->anim.localPosX - *(f32*)(base + 0x08);
        dz = ((GameObject*)obj)->anim.localPosZ - *(f32*)(base + 0x10);
        angleCos = mathSinf((lbl_803DEFE8 * (f32)((ObjSeqState*)seq)->heading) / lbl_803DEFEC);
        angleSin = mathCosf((lbl_803DEFE8 * (f32)((ObjSeqState*)seq)->heading) / lbl_803DEFEC);
        ((GameObject*)obj)->anim.localPosX = angleCos * dz + (angleSin * dx + *(f32*)(base + 0x08));
        ((GameObject*)obj)->anim.localPosZ = -(angleCos * dx - (angleSin * dz + *(f32*)(base + 0x10)));
        return;
    }

    node = (RomCurveNode*)(*gRomCurveInterface)->getById(((ObjSeqState*)seq)->curveId);
    if (node == NULL)
    {
        return;
    }

    dx = ((GameObject*)obj)->anim.localPosX - *(f32*)(base + 0x08);
    dy = ((GameObject*)obj)->anim.localPosY - *(f32*)(base + 0x0c);
    dz = ((GameObject*)obj)->anim.localPosZ - *(f32*)(base + 0x10);
    offset[0] = dx;
    offset[1] = dy;
    offset[2] = dz;
    outPos[0] = ((GameObject*)obj)->anim.localPosX;
    outPos[1] = ((GameObject*)obj)->anim.localPosY;
    outPos[2] = ((GameObject*)obj)->anim.localPosZ;

    if (node->links[0] < 0)
    {
        ((GameObject*)obj)->anim.localPosX = outPos[0];
        ((GameObject*)obj)->anim.localPosY = outPos[1];
        ((GameObject*)obj)->anim.localPosZ = outPos[2];
        return;
    }

    if (RomCurveInterp_EvaluateOffsetPosition(((ObjSeqState*)seq)->curveInterp, offset, outPos,
                                              (s16*)(seq + 0x1a), ((ObjSeqState*)seq)->unk7A) != 0)
    {
        ((GameObject*)obj)->anim.localPosX = outPos[0];
        ((GameObject*)obj)->anim.localPosY = outPos[1];
        ((GameObject*)obj)->anim.localPosZ = outPos[2];
        return;
    }

    angleCos = mathSinf((lbl_803DEFE8 * (f32)((ObjSeqState*)seq)->heading) / lbl_803DEFEC);
    angleSin = mathCosf((lbl_803DEFE8 * (f32)((ObjSeqState*)seq)->heading) / lbl_803DEFEC);
    ((GameObject*)obj)->anim.localPosX = angleCos * dz + (angleSin * dx + *(f32*)(base + 0x08));
    ((GameObject*)obj)->anim.localPosZ = -(angleCos * dx - (angleSin * dz + *(f32*)(base + 0x10)));
}

void animatedObjFreeAndSavePlayerPos(u8* obj, u8* seqObj, u8* seq)
{
    void(*callback)(void *ctx, u8 * obj);
    u8* player;
    int clearBit;

    callback = ((ObjSeqState*)seq)->freeCallback;
    if (callback != NULL)
    {
        callback(((ObjSeqState*)seq)->callbackContext, obj);
        ((ObjSeqState*)seq)->freeCallback = NULL;
    }

    if ((s8)((ObjSeqState*)seq)->slot == lbl_803DB720)
    {
        AudioStream_CancelPrepared();
        lbl_803DB720 = -1;
    }

    if (((ObjSeqState*)seq)->unk7E != 0)
    {
        if ((s8)((ObjSeqState*)seq)->unk7B != 0)
        {
            ((ObjSeqState*)seq)->unk7B = 0;
        }
        if (((ObjSeqState*)seq)->targetObj != NULL)
        {
            *(void**)(seqObj + 0xc0) = NULL;
            ((GameObject*)seqObj)->objectFlags &= ~OBJECT_OBJFLAG_SEQ_ATTACHED;
            ((ObjSeqState*)seq)->targetObj = NULL;
        }
    }

    if ((((u32)((ObjSeqState*)seq)->flags136[0] >> 2) & 1U) != 0U)
    {
        player = Obj_GetPlayerObject();
        (*gMapEventInterface)->savePoint((int)(player + 0xc), ((GameObject*)player)->anim.rotX, 0,
                                            getCurMapLayer());
        clearBit = 0;
        {
            struct SeqByte136
            {
                u8 b80 : 1, b40 : 1, b20 : 1, b10 : 1, b08 : 1, b04 : 1, b02 : 1, b01 : 1;
            };
            ((struct SeqByte136*)&((ObjSeqState*)seq)->flags136[0])->b04 = clearBit;
        }
    }

    ((ObjSeqState*)seq)->unk7E = 0;
}

f32 objCurveInterpolate(ObjCurveKey* keys, int count, int frame)
{
    int index;
    int mode;
    int prevIndex;
    int keyIndex;
    ObjCurveKey* key;
    ObjCurveKey* prev;
    f32 values[4];
    f32 deltaNext;
    f32 deltaPrev;
    f32 span;
    f32 t;

    if (count <= 0)
    {
        return lbl_803DEFB0;
    }

    index = 0;
    while (index < count && keys[index].frame < frame)
    {
        index++;
    }

    if (index == count)
    {
        return keys[count - 1].value;
    }
    if (index == 0)
    {
        return keys[0].value;
    }
    if (frame == keys[index].frame)
    {
        t = keys[index].value;
        mode = keys[index].tangentAndMode & 3;
        if (mode > 1 && index < count - 1)
        {
            t = keys[index + 1].value;
        }
        return t;
    }

    prevIndex = index - 1;
    prev = &keys[prevIndex];
    mode = prev->tangentAndMode & 3;
    values[0] = prev->value;
    if (mode == 0)
    {
        deltaNext = prev[1].value - values[0];
        if (prevIndex > 0)
        {
            deltaPrev = values[0] - prev[-1].value;
        }
        else
        {
            deltaPrev = deltaNext;
        }
        if (deltaNext < lbl_803DEFB0)
        {
            deltaNext = -deltaNext;
        }
        if (deltaPrev < *(f32*)&lbl_803DEFB0)
        {
            deltaPrev = -deltaPrev;
        }
        deltaPrev = deltaNext + deltaPrev;
        t = deltaPrev * lbl_803DF000;
        values[2] = t * (f32)(prev->tangentAndMode >> 2);
    }

    span = (f32)(keys[prevIndex + 1].frame - keys[prevIndex].frame);
    keyIndex = index;
    if (index < count)
    {
        key = &keys[keyIndex];
        values[1] = key->value;
        if (mode == 0)
        {
            index++;
            if (index < count)
            {
                deltaPrev = key[1].value - values[1];
            }
            else
            {
                deltaPrev = deltaNext;
            }
            if (deltaPrev < lbl_803DEFB0)
            {
                deltaPrev = -deltaPrev;
            }
            deltaPrev = deltaNext + deltaPrev;
            t = deltaPrev * lbl_803DF000;
            values[3] = t * (f32)(keys[keyIndex].tangentAndMode >> 2);
        }
    }

    if (span > lbl_803DEFB0)
    {
        t = (f32)(frame - keys[keyIndex - 1].frame) / span;
        if (mode == 0)
        {
            return Curve_EvalHermite(t, values, NULL);
        }
        if (mode == 1)
        {
            return t * (values[1] - values[0]) + values[0];
        }
        return values[1];
    }
    return values[1];
}

/* .bss block 0x80396918-0x8039A7A8 */
u8 lbl_80396918[0x2A80];
s16 gObjSeqBgCmds[0x5A];
u8 lbl_8039944C[0xA0];
f32 objSeqOverridePos[0x259];
u8 lbl_80399E50[0x58];
u8 objSeqXrotChanged[0x58];
s16 objSeqXrotValues[0x156];
f32 gObjSeqSlotStreamTimeTable[0x81];
s16 gObjSeqSlotSeqIdTable[0x56];
s8 gObjSeqBoolFlags[0x58];
s8 gObjSeqCondFlags[0x58];
s8 gObjSeqSlotResults[0xB0];
ObjSeqBgCmd lbl_8039A5BC[0x50 / sizeof(ObjSeqBgCmd)];
s8 gObjSeqJumpLatch[0x58];
int gObjSeqPreemptList[40][2];

int gObjSeqMsgIds[] = {
    0x00050001, 0x00050002, 0x00050003, 0x00060001,
    0x00060002, 0x000A0001, 0x000A0002, 0x000A0003,
    8, 9, 0x00030002, 0x00030003,
    0x000A0004, 0x000A0005, 0x000A0006, 0x000F000B,
    0x000F000C, 0x000F000D, 0x000F000E, 0x000F000F,
    0x000F0010, 0x00130001, 0x00130002,
};

/* --- objseq .data reconstruction (absorbed range 0x8030ECA8-0x8030EF58) --- */
extern u8 lbl_8030EC00[];
extern u8 lbl_8030EC10[];
extern u8 lbl_8030EC1C[];
extern u8 lbl_8030EC28[];
extern u8 lbl_8030EC44[];
extern u8 lbl_8030EC54[];
extern u8 lbl_8030EC64[];
extern u8 lbl_8030EC70[];
extern u8 lbl_8030EC7C[];
extern u8 lbl_8030EC98[];
extern void ObjSeq_preempt();
extern void ObjSeq_yield();
extern void ObjSeq_getGlobal3();
extern void ObjSeq_setGlobal3();
extern void ObjSeq_getGlobal1();
extern void ObjSeq_setGlobal1();
extern void ObjSeq_getGlobal2();
extern void ObjSeq_setGlobal2();
extern void ObjSeq_SetObjs();
extern void ObjSeq_setOverridePos();
extern void ObjSeq_func23();

int gObjSeqStreamTableA[10] = {
    0x35F, (int)lbl_8030EC00,
    0x45A, (int)lbl_8030EC10,
    0x117, (int)lbl_8030EC1C,
    0xC3, (int)lbl_8030EC28,
    0x122, (int)lbl_8030EC44
};
int gObjSeqStreamTableB[10] = {
    0x35F, (int)lbl_8030EC54,
    0x45A, (int)lbl_8030EC64,
    0x117, (int)lbl_8030EC70,
    0xC3, (int)lbl_8030EC7C,
    0x122, (int)lbl_8030EC98
};

s16 lbl_8030ECF8[86] = { 0 };

int lbl_8030EDA4[7] = { 0x100, 0x200, 0x40000, 0x80000, 0x20000, 0x10000, -1 };

s8 gObjSeqMsgSendModes[24] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0 };

void* lbl_8030EE34[40] = {
    (void*)0,
    (void*)0,
    (void*)0,
    (void*)0x230000,
    (void*)ObjSeq_initialise,
    (void*)ObjSeq_release,
    (void*)0,
    (void*)objSeq_onMapSetup,
    (void*)ObjSeq_addBgCmd,
    (void*)ObjSeq_setFlag,
    (void*)ObjSeq_getBool,
    (void*)ObjSeq_update,
    (void*)ObjSeq_updateCamera,
    (void*)ObjSeq_objLoadAnimData,
    (void*)ObjSeq_seqState_init,
    (void*)ObjSeq_seqState_free,
    (void*)ObjSeq_run,
    (void*)ObjSeq_ResolveAndAssignTargetObject,
    (void*)fn_8008194C,
    (void*)fn_80081964,
    (void*)fn_8008195C,
    (void*)fn_80081954,
    (void*)fn_80081944,
    (void*)fn_80081940,
    (void*)objRunSeq,
    (void*)endObjSequence,
    (void*)ObjSeq_setCamVars,
    (void*)ObjSeq_preempt,
    (void*)ObjSeq_yield,
    (void*)ObjSeq_getGlobal3,
    (void*)ObjSeq_setGlobal3,
    (void*)ObjSeq_getGlobal1,
    (void*)ObjSeq_setGlobal1,
    (void*)ObjSeq_getGlobal2,
    (void*)ObjSeq_setGlobal2,
    (void*)ObjSeq_setXrot,
    (void*)ObjSeq_func20,
    (void*)ObjSeq_SetObjs,
    (void*)ObjSeq_setOverridePos,
    (void*)ObjSeq_func23
};

char sEndObjSequenceMaxFreesError[41] = "endObjSequence: max number of obj frees\n\000";
char sObjSequenceMissingObjectFormat[38] = " SEQUENCE: Could not Find Object %i \n\000";
char sObjLoadAnimdataNullACRomTabWarning[45] = "<objLoadAnimdata>  Warning ACRomTab is NULL\n\000";

