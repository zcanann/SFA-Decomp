#ifndef MAIN_DLL_DLL_00C4_TRICKY_H_
#define MAIN_DLL_DLL_00C4_TRICKY_H_

#include "game/objects/object.h"

#define TRICKY_ITEM_ID_COUNT 5

#define TRICKY_COMMAND_KIND_NORMAL   0
#define TRICKY_COMMAND_KIND_PRIORITY 1

typedef struct TrickyItemIdList {
    s32 ids[TRICKY_ITEM_ID_COUNT];
} TrickyItemIdList;

STATIC_ASSERT(sizeof(TrickyItemIdList) == 0x14);

extern const TrickyItemIdList gTrickyCmdQueryInit;
extern const TrickyItemIdList gTrickyFoodItemIds;
#include "types.h"
#include "main/dll/tricky_state.h"
#include "main/objseq.h"
#include "dlls/object_descriptor.h"

extern ObjectDescriptor21 gTrickyObjDescriptor;

/* gTrickyObjDescriptor from slot02 onwards: the export table other objects reach through
   obj->anim.dll. */
typedef struct TrickyCompanionInterface {
    void* pad00[8];
    int (*getAvailableCommands)(GameObject* tricky);
    int (*updateSideCommandPrompts)(GameObject* tricky);
    void (*sideCommandEnable)(GameObject* tricky, GameObject* target, int commandKind, int commandType);
    u8 (*getEnergy)(GameObject* tricky);
    u8 (*getEnergyMax)(GameObject* tricky);
    void (*commandPlayBall)(GameObject* tricky, int enabled, GameObject* target);
    int (*requestMoveToObject)(GameObject* tricky, GameObject* target);
    void (*requestRecall)(GameObject* tricky);
    u8 (*isPlayingBall)(GameObject* tricky);
    u8 (*isGuarding)(GameObject* tricky);
    int (*getCurrentCommandType)(GameObject* tricky, int* commandType);
} TrickyCompanionInterface;

STATIC_ASSERT(offsetof(TrickyCompanionInterface, getAvailableCommands) == 0x20);
STATIC_ASSERT(offsetof(TrickyCompanionInterface, updateSideCommandPrompts) == 0x24);
STATIC_ASSERT(offsetof(TrickyCompanionInterface, sideCommandEnable) == 0x28);
STATIC_ASSERT(offsetof(TrickyCompanionInterface, getEnergy) == 0x2C);
STATIC_ASSERT(offsetof(TrickyCompanionInterface, getEnergyMax) == 0x30);
STATIC_ASSERT(offsetof(TrickyCompanionInterface, commandPlayBall) == 0x34);
STATIC_ASSERT(offsetof(TrickyCompanionInterface, requestMoveToObject) == 0x38);
STATIC_ASSERT(offsetof(TrickyCompanionInterface, requestRecall) == 0x3C);
STATIC_ASSERT(offsetof(TrickyCompanionInterface, isPlayingBall) == 0x40);
STATIC_ASSERT(offsetof(TrickyCompanionInterface, isGuarding) == 0x44);
STATIC_ASSERT(offsetof(TrickyCompanionInterface, getCurrentCommandType) == 0x48);

#define TRICKY_INTERFACE(tricky) ((TrickyCompanionInterface*)*((GameObject*)(tricky))->anim.dll)

void trickyReportError(const char* fmt, ...);
void trickyDebugPrint(const char* fmt, ...);
GameObject* Tricky_findNearestGroup4BObject(GameObject* obj, TrickyState* state);
void tricky_attachToWalkGroup(GameObject* obj, TrickyState* state);
void tricky_stateIdleWander(GameObject* obj, TrickyState* state);
int Tricky_requestMoveToObject(GameObject* obj, GameObject* targetObj);
void Tricky_commandPlayBall(GameObject* obj, int commandEnabled, GameObject* targetObj);
void sideCommandEnable(GameObject* obj, GameObject* targetObj, int commandKind, int commandType);
int Tricky_updateSideCommandPrompts(GameObject* obj);
void Tricky_free(GameObject* obj, int shouldKeepFlameChildren);
void Tricky_init(GameObject* obj);
int tricky_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate);
void Tricky_update(GameObject* obj);
void Tricky_render(GameObject* obj, int p2, int p3, int p4, int p5, char doRender);
void Tricky_hitDetect(GameObject* obj);
int Tricky_getExtraSize(void);
u8 Tricky_getEnergyMax(GameObject* obj);
u8 Tricky_getEnergy(GameObject* obj);
int Tricky_getCurrentCommandType(GameObject* obj, int* out);
void Tricky_requestRecall(GameObject* obj);
int Tricky_isGuarding(GameObject* obj);
int Tricky_isPlayingBall(GameObject* obj);
int Tricky_getAvailableCommands(GameObject* obj);

#endif /* MAIN_DLL_DLL_00C4_TRICKY_H_ */
