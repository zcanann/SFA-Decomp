#ifndef MAIN_DLL_DLL_00C4_TRICKY_H_
#define MAIN_DLL_DLL_00C4_TRICKY_H_

#include "game/objects/object.h"
#include "game/objects/object_interface.h"

#define TRICKY_COMMAND_QUERY_COUNT 5

enum TrickyCommandKind {
    TRICKY_COMMAND_KIND_NORMAL = 0,
    TRICKY_COMMAND_KIND_PRIORITY = 1
};

/*
 * Sidekick command active IDs. These are also the activeGameBit values in
 * gCMenuTrickyAbilities; DISTRACT is the prompt-only Baddie Alert branch that
 * uses the shared Find Secret icon slot but has no normal C-menu entry.
 */
enum TrickyCommandType {
    TRICKY_COMMAND_TYPE_CALL = 0,
    TRICKY_COMMAND_TYPE_FIND_SECRET = 1,
    TRICKY_COMMAND_TYPE_DISTRACT = 2,
    TRICKY_COMMAND_TYPE_STAY = 3,
    TRICKY_COMMAND_TYPE_FLAME = 4,
    TRICKY_COMMAND_TYPE_PLAY_BALL = 5
};

#define TRICKY_COMMAND_TYPE_TO_FLAG(commandType) (1 << (commandType))

typedef struct TrickyCommandTypeList {
    s32 commandTypes[TRICKY_COMMAND_QUERY_COUNT];
} TrickyCommandTypeList;

STATIC_ASSERT(sizeof(TrickyCommandTypeList) == 0x14);

extern const TrickyCommandTypeList gTrickyCommandQueryInit;
extern const TrickyCommandTypeList gTrickyFoodCommandQuery;
#include "types.h"
#include "main/dll/tricky_state.h"
#include "main/objseq.h"
#include "dlls/object_descriptor.h"

extern ObjectDescriptor21 gTrickyObjDescriptor;

/* gTrickyObjDescriptor from slot02 onwards: the export table other objects reach through
   obj->anim.dll. */
typedef struct TrickyCompanionInterface {
    ObjectInterface base;
    int (*getAvailableCommands)(GameObject* tricky);
    int (*updateSideCommandPrompts)(GameObject* tricky);
    void (*sideCommandEnable)(GameObject* tricky, GameObject* target, enum TrickyCommandKind commandKind,
                              enum TrickyCommandType commandType);
    u8 (*getEnergy)(GameObject* tricky);
    u8 (*getEnergyMax)(GameObject* tricky);
    void (*commandPlayBall)(GameObject* tricky, int enabled, GameObject* target);
    int (*requestMoveToObject)(GameObject* tricky, GameObject* target);
    void (*requestRecall)(GameObject* tricky);
    u8 (*isPlayingBall)(GameObject* tricky);
    u8 (*isGuarding)(GameObject* tricky);
    int (*getCurrentCommandPhase)(GameObject* tricky, int* commandPhase);
} TrickyCompanionInterface;

STATIC_ASSERT(offsetof(TrickyCompanionInterface, base) == 0);
STATIC_ASSERT(sizeof(TrickyCompanionInterface) == 0x4C);
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
STATIC_ASSERT(offsetof(TrickyCompanionInterface, getCurrentCommandPhase) == 0x48);

#define TRICKY_INTERFACE(tricky) ((TrickyCompanionInterface*)*((GameObject*)(tricky))->anim.dll)

void trickyReportError(const char* fmt, ...);
void trickyDebugPrint(const char* fmt, ...);
GameObject* trickyFindRecallWarp(GameObject* obj, TrickyState* state);
void tricky_attachToWalkGroup(GameObject* obj, TrickyState* state);
void tricky_stateIdleWander(GameObject* obj, TrickyState* state);
int Tricky_requestMoveToObject(GameObject* obj, GameObject* targetObj);
void Tricky_commandPlayBall(GameObject* obj, int commandEnabled, GameObject* targetObj);
void sideCommandEnable(GameObject* obj, GameObject* targetObj, enum TrickyCommandKind commandKind,
                       enum TrickyCommandType commandType);
int Tricky_updateSideCommandPrompts(GameObject* obj);
void Tricky_free(GameObject* obj, int shouldKeepFlameChildren);
void Tricky_init(GameObject* obj);
int tricky_SeqFn(GameObject* obj, int unused, ObjSeqState* sequence);
void Tricky_update(GameObject* obj);
void Tricky_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, char doRender);
void Tricky_hitDetect(GameObject* obj);
int Tricky_getExtraSize(void);
u8 Tricky_getEnergyMax(GameObject* obj);
u8 Tricky_getEnergy(GameObject* obj);
int Tricky_getCurrentCommandPhase(GameObject* obj, int* outCommandPhase);
void Tricky_requestRecall(GameObject* obj);
u8 Tricky_isGuarding(GameObject* obj);
u8 Tricky_isPlayingBall(GameObject* obj);
int Tricky_getAvailableCommands(GameObject* obj);

#endif /* MAIN_DLL_DLL_00C4_TRICKY_H_ */
