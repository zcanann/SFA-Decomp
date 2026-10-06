#!/usr/bin/env python3
"""Check map player/camera setup with real settings records and independent native globals."""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PRELUDE = r'''
#include <assert.h>
#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
typedef uint8_t u8; typedef int8_t s8; typedef uint16_t u16; typedef int16_t s16;
typedef uint32_t u32; typedef int32_t s32; typedef float f32;
#define STATIC_ASSERT(x) _Static_assert(x,#x)
typedef struct { f32 x,y,z; } Vec3f;
/* Adapt only dependencies outside the recovered storage and placement contract. */
typedef struct { const char* name; } ModelDef;
typedef struct GameObject {
    void* hostPrefix[3];
    struct { float localPosX,localPosY,localPosZ; ModelDef* modelInstance; } anim;
} GameObject;
typedef struct CameraObject {
    void* hostPrefix[2];
    struct { float worldPosX,worldPosY,worldPosZ,localPosX,localPosY,localPosZ;
             s16 rotX,rotY,rotZ; GameObject* parent; } anim;
    GameObject* focusObject; float fovY,prevWorldX,prevWorldY,prevWorldZ;
    Vec3f savedLocalPos; s8 letterboxTargetOffset; u8 unk13E;
} CameraObject;
typedef struct { void* hostPrefix; float x,y,z; } Camera;
'''
SERVICES = r'''
static CameraModeNormalState state;
CameraModeNormalState* gCameraModeNormalState=&state;
static GameObject player,fallback;
static ModelDef definition={"test player"};
static CameraObject cameraObject;
static Camera viewport;
static SaveGameCharacterPosition saved;
static int mapType,character,ui,locked,loadSucceeds,cases,eventsCount;
static char events[80];
static void event(char c) { assert(eventsCount<79); events[eventsCount++]=c; events[eventsCount]=0; }
static void closeFloat(float a,float b) { assert(fabsf(a-b)<0.001f); }
static GameObject* expectedPlayer(void) {
    return character>=0 && mapType!=4 && !locked && loadSucceeds ? &player : NULL;
}
static float expectedX(void) { return saved.x+60.0f*sinf(3.1415927f*(saved.angle*256)/32768.0f); }
static float expectedZ(void) { return saved.z+60.0f*cosf(3.1415927f*(saved.angle*256)/32768.0f); }
static int getCurMapType(void) { event('M'); return mapType; }
static int getCurChar(void) { event('C'); return character; }
static SaveGameCharacterPosition* getCurCharPos(void) { event('P'); return &saved; }
static struct { int (*getCurChar)(void); SaveGameCharacterPosition* (*getCurCharPos)(void); }
    mapInterface={getCurChar,getCurCharPos}, *mapPointer=&mapInterface, **gMapEventInterface=&mapPointer;
static void OSReport(char* format,...) {
    va_list args; va_start(args,format);
    char output[256]; vsnprintf(output,sizeof(output),format,args); va_end(args);
    if (strcmp(format,"=======  OBJFREEALL \n")==0) event('R');
    else if (strncmp(format,"\n\n\n\n\n\n\n    LOADING CHARACTER",28)==0) {
        char expected[256]; snprintf(expected,sizeof(expected),
          "\n\n\n\n\n\n\n    LOADING CHARACTER     maptype %d  playerno %d\n\n\n\n\n\n\n",mapType,character);
        assert(strcmp(output,expected)==0); event('L');
    } else if (strncmp(format,"<objSetupObject>",16)==0) {
        assert(strcmp(output,"<objSetupObject>  loading is locked can't setup objno -1\n")==0); event('W');
    } else { assert(strcmp(output,"LOADED OBJECT test player\n")==0); event('O'); }
}
static void Obj_ResetObjectSystem(void) { event('D'); }
static int getLoadedFileFlags(int index) { assert(index==0); event('F'); return locked ? 0x100000 : 0; }
static GameObject* loadCharacter(ObjPlacement* p,int flags,int layer,int index,GameObject* parent,int unused) {
    assert((uintptr_t)p>UINT32_MAX);
    assert(flags==1 && layer==-1 && index==-1 && !parent && unused==0);
    assert(p->objectId==(character==0 ? 31 : 0) && p->ident==-1 && p->size==24);
    assert(p->mapActFlagsLo==0 && p->loadFlags==1 && p->mapActFlagsHi==4 && p->loadRange==255 && p->unk07==255);
    assert(p->posX==saved.x && p->posY==saved.y && p->posZ==saved.z);
    event('A'); return loadSucceeds ? &player : NULL;
}
static void Obj_RegisterObject(GameObject* object,int flags) { assert(object==&player && flags==1); event('B'); }
static float mathSinf(float x) { event('S'); return sinf(x); }
static float mathCosf(float x) { event('T'); return cosf(x); }
static int getCurUiDll(void) { event('U'); return ui; }
static void camcontrol_getTargetPosition(CameraObject* cam,void* target,float* pos,s16* yaw) {
    assert(cam==&cameraObject && target==&cam->focusObject->anim);
    pos[0]=71; pos[1]=82; pos[2]=93; *yaw=345;
}
static void Obj_TransformWorldPointToLocal(float x,float y,float z,float* ox,float* oy,float* oz,GameObject* parent) {
    (void)parent; *ox=x; *oy=y; *oz=z;
}
static s16 getAngle(float y,float x) { (void)y; (void)x; return 321; }
static void getRelativePosition(void* object,float* x,float* y,float* z,float* distance,float height,int mode) {
    (void)object;(void)height;(void)mode;*x=1;*y=2;*z=3;*distance=4;
}
static void CameraModeNormal_init(CameraObject*,int,CameraModeNormalInitSettings*);
static void init(void* focus,float x,float y,float z) {
    assert(focus==expectedPlayer()); closeFloat(x,expectedX());closeFloat(y,saved.y+40);closeFloat(z,expectedZ());
    cameraObject.focusObject=focus ? focus : &fallback; cameraObject.fovY=51; event('I');
}
static void setMode(int mode,int unused,int action,int size,void* params,int frames,int priority) {
    assert(unused==0 && frames==0);event('K');
    if (ui>=2 && ui<=7) { assert(mode==0x57 && action==3 && size==0 && !params && priority==0); }
    else {
        assert(mode==0x42 && action==0 && size==32 && params==&gObjInitialCameraSettings && priority==255);
        assert((uintptr_t)params>UINT32_MAX);
        CameraModeNormal_init(&cameraObject,0,params);
        assert(state.minDistance==85 && state.maxDistance==90 && cameraObject.fovY==60);
        assert(state.lowerHeightOffset==20 && state.upperHeightOffset==20 && state.targetHeight==35);
    }
}
static void setFocus(void* focus,int unused) { assert(focus==expectedPlayer() && unused==0);event('J'); }
static void update(u8 frames) {
    assert(frames==1);event('V');cameraObject.anim.worldPosX=101;cameraObject.anim.worldPosY=202;cameraObject.anim.worldPosZ=303;
}
static void* getCamera(void) { event('G');return &cameraObject; }
static struct {
    void (*init)(void*,float,float,float);
    void (*setMode)(int,int,int,int,void*,int,int);
    void (*setFocus)(void*,int); void (*update)(u8); void* (*getCamera)(void);
    void (*getRelativePosition)(void*,float*,float*,float*,float*,float,int);
} cameraInterface={init,setMode,setFocus,update,getCamera,getRelativePosition},
  *cameraPointer=&cameraInterface, **gCameraInterface=&cameraPointer;
static Camera* Camera_GetCurrent(void) { event('H');return &viewport; }
static void focusPlayer(GameObject* p) { assert(p==expectedPlayer());event('Q'); }
static struct { void (*func07)(GameObject*); } titleVtable={focusPlayer};
static struct { void* hostPrefix; typeof(titleVtable)* vtable; } titleInterface={NULL,&titleVtable},
    *gTitleMenuControlInterface=&titleInterface;
static void mapUpdateCameraPosByTransformSpace(void) { event('Z'); }
static int lbl_803DCB70;
'''
CHECKS = r'''
static void checkSetup(void) {
    eventsCount=0;events[0]=0;viewport.x=-1;viewport.y=-2;viewport.z=-3;lbl_803DCB70=7;
    CameraModeNormalInitSettings before=gObjInitialCameraSettings;
    mapSetupPlayer();
    char expected[80]="M";
    if (mapType==2 || mapType==3) {
        strcat(expected,"RD");assert(viewport.x==-1 && viewport.y==-2 && viewport.z==-3 && lbl_803DCB70==7);
        assert(memcmp(&before,&gObjInitialCameraSettings,sizeof(before))==0);
    } else {
        strcat(expected,"CP");
        if (character>=0 && mapType!=4) strcat(expected,locked ? "LFW" : loadSucceeds ? "LFABO" : "LFA");
        strcat(expected,ui>=2 && ui<=7 ? "STUIKJVHGQZ" : "STUIKVHGQZ");
        closeFloat(gObjInitialCameraSettings.initial.x,expectedX());
        closeFloat(gObjInitialCameraSettings.initial.y,saved.y+40);
        closeFloat(gObjInitialCameraSettings.initial.z,expectedZ());
        before.initial.x=gObjInitialCameraSettings.initial.x;before.initial.y=gObjInitialCameraSettings.initial.y;
        before.initial.z=gObjInitialCameraSettings.initial.z;
        assert(memcmp(&before,&gObjInitialCameraSettings,sizeof(before))==0);
        assert(viewport.x==101 && viewport.y==202 && viewport.z==303 && lbl_803DCB70==0);
    }
    assert(strcmp(events,expected)==0);cases++;
}
static void checkTransition(int value) {
    CameraModeNormalInitSettings settings={0};
    settings.transition.transitionFrames=(s8)value;settings.transition.fov=(s8)(value^128);
    settings.transition.minDistance=value;settings.transition.maxDistance=255-value;
    settings.transition.lowerHeightOffset=value/2;settings.transition.upperHeightOffset=200;
    settings.transition.letterboxOffset=value;settings.transition.slideRightAmount=12;settings.transition.slideLeftAmount=24;
    settings.transition.distanceAdjustRate=value;settings.transition.heightAdjustRate=255-value;
    settings.transition.snapToTarget=value&1;
    memset(&state,0,sizeof(state));state.minDistance=501;state.maxDistance=502;state.targetHeight=503;
    state.lowerHeightOffset=504;state.upperHeightOffset=505;state.distanceAdjustRate=0.3f;state.heightAdjustRate=0.4f;
    state.slideRightAmount=506;state.slideLeftAmount=507;cameraObject.fovY=55;cameraObject.focusObject=&player;
    CameraModeNormal_init(&cameraObject,2,&settings);
    assert(state.targetMinDistance==value && state.targetMaxDistance==255-value && state.fov==(s8)(value^128));
    assert(state.baseLowerHeightOffset==value/2 && state.targetLowerHeightOffset==value/2);
    assert(state.baseUpperHeightOffset==200 && state.targetUpperHeightOffset==200);
    assert(state.targetSlideRightAmount==12 && state.targetSlideLeftAmount==24);
    closeFloat(state.targetDistanceAdjustRate,value ? value/255.0f : 0.09f);
    closeFloat(state.targetHeightAdjustRate,value!=255 ? (255-value)/255.0f : 0.09f);
    assert(state.transitionDuration==(s8)value && state.transitionTimer==((value&1) ? 0 : (s8)value));
    assert((u8)cameraObject.letterboxTargetOffset==value && cameraObject.unk13E==1);
    assert(state.savedMinDistance==501 && state.savedMaxDistance==502 && state.savedTargetHeight==503);
    assert(state.savedLowerHeightOffset==504 && state.savedUpperHeightOffset==505 && state.savedFov==55);
    assert(state.savedSlideRightAmount==506 && state.savedSlideLeftAmount==507);
    closeFloat(state.savedDistanceAdjustRate,0.3f);closeFloat(state.savedHeightAdjustRate,0.4f);
    cases++;
}
int main(void) {
    assert(sizeof(void*)==8 && (uintptr_t)&gObjInitialCameraSettings>UINT32_MAX);
    player.anim.modelInstance=&definition;saved.x=123.25f;saved.y=-45.5f;saved.z=908.75f;
    int angles[]={-128,-127,-1,0,1,64,127};
    for (mapType=0;mapType<5;mapType++) for (character=-1;character<2;character++)
    for (ui=-1;ui<10;ui++) for (locked=0;locked<2;locked++) for (loadSucceeds=0;loadSucceeds<2;loadSucceeds++)
    for (int i=0;i<7;i++) { saved.angle=angles[i];checkSetup(); }
    mapType=0;character=0;ui=0;locked=0;loadSucceeds=1;
    for (int i=-128;i<=127;i++) { saved.angle=i;checkSetup(); }
    for (int i=0;i<256;i++) checkTransition(i);
    printf("%d player/camera setup scenarios passed\n",cases);
}
'''


def function(text, name):
    match = re.search(r"^void " + name + r"\([^;]+?\) \{", text, re.M)
    assert match, name
    depth = 1
    end = match.end()
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[match.start():end] + "\n"


def source():
    obj = (ROOT / "src/main/object.c").read_text()
    header = (ROOT / "include/main/dll/dll_0042_cameramodenormal.h").read_text()
    records = header[header.index("typedef union CameraModeNormalInitSettings"):header.index("typedef void (*CameraModeNormalFollowFn)")]
    # This intervening header portion contains only the settings, state and layout assertions.
    placement = (ROOT / "include/game/objects/object_setup.h").read_text()
    placement = re.sub(r'^#include .*$', '', placement, flags=re.M)
    save = (ROOT / "include/main/dll/savegame_state.h").read_text()
    save = re.search(r'typedef struct SaveGameCharacterPosition.*?} SaveGameCharacterPosition;', save, re.S)[0]
    data = obj[obj.index("CameraModeNormalInitSettings gObjInitialCameraSettings"):obj.index("char sObjFreeObjdefError")]
    ids = re.search(r's16 gObjPlayerSpawnIdTable\[2\].*?;', obj)[0]
    constants = '#define MAPTYPE_UNLOAD_UNUSED 2\n#define MAPTYPE_SUBMAP_UNUSED 3\n#define MAPTYPE_NO_HUD 4\n'
    constants += '#define LOADED_FILE_FLAG_PI_LOCKED 0x100000\n#define CAMERA_MODE_TITLE_RESOURCE_ID 0x57\n#define OBJECT_CAMMODE_DEFAULT 0x42\n'
    camera = (ROOT / "src/dlls/engine/66/66.c").read_text()
    return (PRELUDE + records + placement + save + data + ids + "\n" + constants + SERVICES +
            function(camera, "CameraModeNormal_init") + function(obj, "mapSetupPlayer") + CHECKS)


class NativeObjectSetup(unittest.TestCase):
    def test_setup(self):
        compiler = shutil.which("clang")
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory(prefix="sfa-object-setup-") as work:
            path = Path(work) / "setup.c"
            path.write_text(source())
            for level in ("-O0", "-O2"):
                with self.subTest(optimization=level):
                    binary = Path(work) / "setup"
                    subprocess.run([compiler, "-std=gnu11", level, "-g", "-fno-common", "-ffp-contract=off",
                                    "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
                                    "-fno-sanitize-recover=all", str(path), "-o", str(binary)], check=True, timeout=30)
                    subprocess.run([str(binary)], check=True, timeout=30)


if __name__ == "__main__":
    unittest.main()
