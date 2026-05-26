#include "ghidra_import.h"
#include "main/dll/dll_19C.h"

extern undefined8 FUN_80006728();
extern undefined4 FUN_80006770();
extern undefined4 FUN_800067c0();
extern undefined4 FUN_80006824();
extern byte FUN_80006b44();
extern undefined4 FUN_80006b4c();
extern undefined4 FUN_80006b50();
extern undefined4 FUN_80006b54();
extern undefined4 FUN_800175cc();
extern undefined4 FUN_80017620();
extern void* FUN_80017624();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_80017710();
extern uint FUN_80017730();
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a98();
extern int FUN_80017af8();
extern undefined4 FUN_8002fc3c();
extern undefined4 ObjMsg_AllocQueue();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80042b9c();
extern int FUN_80044404();
extern undefined8 FUN_80080f28();
extern undefined4 FUN_8008111c();
extern undefined4 FUN_8014cbbc();
extern undefined4 SH_LevelControl_runBloopEvent();
extern undefined4 FUN_801d8480();
extern int FUN_8028683c();
extern undefined4 FUN_80286888();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294ccc();
extern uint FUN_80294cd0();
extern undefined4 FUN_80294d40();

extern ushort DAT_80326bc8;
extern undefined4 DAT_80326bdc;
extern ushort DAT_80326bf0;
extern int DAT_80326c04;
extern undefined4 DAT_803dcbc8;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd72c;
extern f64 DOUBLE_803e5b18;
extern f64 DOUBLE_803e5b28;
extern f32 lbl_803DC074;
extern f32 lbl_803E5AE8;
extern f32 lbl_803E5AEC;
extern f32 lbl_803E5AF0;
extern f32 lbl_803E5AF4;
extern f32 lbl_803E5B00;
extern f32 lbl_803E5B04;
extern f32 lbl_803E5B08;
extern f32 lbl_803E5B0C;
extern f32 lbl_803E5B10;
extern f32 lbl_803E5B20;
extern f32 lbl_803E5B24;
extern f32 lbl_803E5B30;
extern f32 lbl_803E4E88;
extern void lightFn_8001db6c(int light, int enabled, f32 scale);
extern void objRenderFn_8003b8f4(f32 scale);
extern void objParticleFn_80099d84(int *obj, int kind, int light, f32 scale1, f32 scale2);

/*
 * --INFO--
 *
 * Function: dfsh_shrine_render
 * EN v1.0 Address: 0x801C2E68
 * EN v1.0 Size: 184b
 * EN v1.1 Address: 0x801C2EC8
 * EN v1.1 Size: 852b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void dfsh_shrine_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    void **state;
    void *light;
    s32 isVisible;

    state = *(void ***)(obj + 0xb8);
    isVisible = visible;
    if (isVisible == 0) {
        light = state[0];
        if (light != NULL) {
            lightFn_8001db6c((int)light, 0, lbl_803E4E88);
        }
    } else {
        light = state[0];
        if (light != NULL) {
            lightFn_8001db6c((int)light, 1, lbl_803E4E88);
        }
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E4E88);
        objParticleFn_80099d84((int *)obj, 7, (int)state[0], lbl_803E4E88, lbl_803E4E88);
    }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_801c3134
 * EN v1.0 Address: 0x801C3134
 * EN v1.0 Size: 340b
 * EN v1.1 Address: 0x801C321C
 * EN v1.1 Size: 364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c3134(undefined4 param_1,undefined4 param_2,int param_3)
{
  byte bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  
  iVar2 = FUN_8028683c();
  piVar5 = *(int **)(iVar2 + 0xb8);
  iVar3 = FUN_80017a98();
  *(undefined *)(param_3 + 0x56) = 0;
  for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar4 = iVar4 + 1) {
    bVar1 = *(byte *)(param_3 + iVar4 + 0x81);
    if (bVar1 != 0) {
      if (bVar1 == 7) {
        FUN_80294ccc(iVar3,1,1);
        FUN_80017698(0xbfd,1);
        FUN_80017698(0x956,1);
        (**(code **)(*DAT_803dd72c + 0x44))(0xb,2);
      }
      else if (bVar1 < 7) {
        if (bVar1 == 3) {
          *(byte *)(piVar5 + 7) = *(byte *)(piVar5 + 7) & 0x7f | 0x80;
        }
      }
      else if (bVar1 == 0xf) {
        *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) & 0xbfff;
        if (*piVar5 != 0) {
          FUN_800175cc((double)lbl_803E5B20,*piVar5,'\0');
        }
      }
      else if ((bVar1 < 0xf) && (0xd < bVar1)) {
        *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
        if (*piVar5 != 0) {
          FUN_800175cc((double)lbl_803E5B20,*piVar5,'\0');
        }
      }
    }
    *(undefined *)(param_3 + iVar4 + 0x81) = 0;
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c3288
 * EN v1.0 Address: 0x801C3288
 * EN v1.0 Size: 148b
 * EN v1.1 Address: 0x801C3388
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c3288(int param_1)
{
  uint uVar1;
  int iVar2;
  uint *puVar3;
  
  puVar3 = *(uint **)(param_1 + 0xb8);
  uVar1 = *puVar3;
  if (uVar1 != 0) {
    FUN_80017620(uVar1);
    *puVar3 = 0;
  }
  FUN_80006b4c();
  iVar2 = FUN_80044404(0x1f);
  FUN_80042b9c(iVar2,1,0);
  FUN_800067c0((int *)0xd8,0);
  FUN_800067c0((int *)0xd9,0);
  FUN_800067c0((int *)0x8,0);
  FUN_80017698(0xefa,0);
  FUN_80017698(0xcbb,1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c331c
 * EN v1.0 Address: 0x801C331C
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x801C341C
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c331c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  int iVar1;
  int *piVar2;
  
  iVar1 = FUN_8028683c();
  piVar2 = *(int **)(iVar1 + 0xb8);
  if (visible == 0) {
    if (*piVar2 != 0) {
      FUN_800175cc((double)lbl_803E5B20,*piVar2,'\0');
    }
  }
  else {
    if (*piVar2 != 0) {
      FUN_800175cc((double)lbl_803E5B20,*piVar2,'\x01');
    }
    FUN_8003b818(iVar1);
    FUN_8008111c((double)lbl_803E5B20,(double)lbl_803E5B20,iVar1,7,(int *)*piVar2);
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c33b4
 * EN v1.0 Address: 0x801C33B4
 * EN v1.0 Size: 1768b
 * EN v1.1 Address: 0x801C34D8
 * EN v1.1 Size: 1508b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c33b4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9)
{
  float fVar1;
  bool bVar2;
  double dVar3;
  float fVar4;
  uint uVar5;
  int iVar6;
  byte bVar7;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  short sVar9;
  int *piVar8;
  ushort *puVar10;
  int iVar11;
  ushort *puVar12;
  undefined8 uVar13;
  
  puVar12 = &DAT_80326bc8;
  iVar11 = *(int *)(param_9 + 0x5c);
  iVar6 = FUN_80017a98();
  if ((*(int *)(param_9 + 0x7a) != 0) &&
     (*(int *)(param_9 + 0x7a) = *(int *)(param_9 + 0x7a) + -1, *(int *)(param_9 + 0x7a) == 0)) {
    uVar13 = FUN_80080f28(7,'\x01');
    uVar13 = FUN_80006728(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                          iVar6,0x78,0,in_r7,in_r8,in_r9,in_r10);
    uVar13 = FUN_80006728(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                          iVar6,0x79,0,in_r7,in_r8,in_r9,in_r10);
    FUN_80006728(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar6,0x222,
                 0,in_r7,in_r8,in_r9,in_r10);
  }
  dfsh_shrine_render((int)param_9, 0, 0, 0, 0, 1);
  if (DAT_803dcbc8 != '\0') {
    *(undefined4 *)(param_9 + 0xc) = *(undefined4 *)(param_9 + 6);
    *(undefined4 *)(param_9 + 0xe) = *(undefined4 *)(param_9 + 8);
    *(undefined4 *)(param_9 + 0x10) = *(undefined4 *)(param_9 + 10);
    FUN_80294d40(iVar6,0x14);
    FUN_80017698(0x1d7,1);
    DAT_803dcbc8 = '\0';
  }
  FUN_801d8480(iVar11 + 0xc,1,-1,-1,0xcbb,(int *)0x8);
  SH_LevelControl_runBloopEvent(iVar11 + 0xc,4,-1,-1,0xcbb,(int *)0xc4);
  fVar4 = lbl_803E5B24;
  dVar3 = DOUBLE_803e5b18;
  uVar5 = (int)*(short *)(iVar11 + 0x12) ^ 0x80000000;
  if ((float)((double)CONCAT44(0x43300000,uVar5) - DOUBLE_803e5b18) <= lbl_803E5B24) {
    switch(*(undefined *)(iVar11 + 0x1a)) {
    case 0:
      fVar1 = *(float *)(iVar11 + 8) - lbl_803DC074;
      *(float *)(iVar11 + 8) = fVar1;
      if (fVar1 <= fVar4) {
        FUN_80006824((uint)param_9,0x343);
        uVar5 = randomGetRange(500,1000);
        *(float *)(iVar11 + 8) =
             (f32)(s32)(uVar5);
      }
      if ((*(byte *)((int)param_9 + 0xaf) & 1) != 0) {
        FUN_80017698(0x589,0);
        *(undefined *)(iVar11 + 0x1a) = 5;
        FUN_800067c0((int *)0xd8,1);
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_9,0xffffffff);
        FUN_80017698(0x129,0);
      }
      break;
    case 1:
      if (*(char *)(iVar11 + 0x1c) < '\0') {
        *(undefined *)(iVar11 + 0x1a) = 2;
        FUN_80017698(0xb76,1);
        FUN_80006b54(0x19,0xd2);
        FUN_80006b50();
      }
      break;
    case 2:
      if ((*(byte *)(iVar11 + 0x1b) < 10) &&
         (*(float *)(iVar11 + 4) = *(float *)(iVar11 + 4) - lbl_803DC074,
         *(float *)(iVar11 + 4) <= fVar4)) {
        FUN_80017698((uint)(ushort)(&DAT_80326bc8)[*(byte *)(iVar11 + 0x1b)],1);
        *(float *)(iVar11 + 4) =
             (float)((double)CONCAT44(0x43300000,
                                      (uint)*(ushort *)
                                             (&DAT_80326bdc + (uint)*(byte *)(iVar11 + 0x1b) * 2)) -
                    DOUBLE_803e5b28);
        *(char *)(iVar11 + 0x1b) = *(char *)(iVar11 + 0x1b) + '\x01';
      }
      bVar2 = false;
      for (sVar9 = 0; sVar9 < 10; sVar9 = sVar9 + 1) {
        uVar5 = FUN_80017690((uint)(ushort)(&DAT_80326bf0)[sVar9]);
        if (uVar5 == 0) {
          bVar2 = true;
          sVar9 = 10;
        }
      }
      if (bVar2) {
        bVar7 = FUN_80006b44();
        if (bVar7 != 0) {
          *(undefined *)(iVar11 + 0x1a) = 7;
          *(byte *)(iVar11 + 0x1c) = *(byte *)(iVar11 + 0x1c) & 0xbf;
          *(undefined2 *)(iVar11 + 0x12) = 0x78;
          piVar8 = &DAT_80326c04;
          for (sVar9 = 0; sVar9 < 10; sVar9 = sVar9 + 1) {
            if ((*piVar8 != -1) && (iVar6 = FUN_80017af8(*piVar8), iVar6 != 0)) {
              FUN_8014cbbc(iVar6);
            }
            piVar8 = piVar8 + 1;
          }
        }
      }
      else {
        *(undefined *)(iVar11 + 0x1a) = 7;
        *(byte *)(iVar11 + 0x1c) = *(byte *)(iVar11 + 0x1c) & 0xbf | 0x40;
        FUN_80006b4c();
      }
      break;
    case 3:
      uVar5 = FUN_80294cd0(iVar6,1);
      if ((uVar5 == 0) && (uVar5 = FUN_80017690(0xbfd), uVar5 == 0)) {
        if ((*(byte *)(iVar11 + 0x1c) >> 6 & 1) == 0) {
          *(undefined *)(iVar11 + 0x1a) = 4;
          FUN_80017698(0xb70,1);
        }
        else {
          *(undefined *)(iVar11 + 0x1a) = 4;
          FUN_80006770(3);
          (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_9,0xffffffff);
        }
      }
      else {
        *(undefined *)(iVar11 + 0x1a) = 4;
      }
      FUN_80017698(0x129,1);
      FUN_80017698(0xb76,0);
      break;
    case 4:
      *(undefined *)(iVar11 + 0x1a) = 0;
      *(byte *)(iVar11 + 0x1c) = *(byte *)(iVar11 + 0x1c) & 0x7f;
      *(undefined *)(iVar11 + 0x1b) = 0;
      *(float *)(iVar11 + 4) = fVar4;
      FUN_80017698(0x129,1);
      FUN_80017698(0xb70,0);
      FUN_80017698(0xb71,0);
      FUN_80017698(0xb76,0);
      FUN_80017698(0x589,1);
      puVar10 = &DAT_80326bf0;
      for (sVar9 = 0; sVar9 < 10; sVar9 = sVar9 + 1) {
        FUN_80017698((uint)*puVar10,0);
        FUN_80017698((uint)*puVar12,0);
        puVar10 = puVar10 + 1;
        puVar12 = puVar12 + 1;
      }
      param_9[3] = param_9[3] & 0xbfff;
      break;
    case 5:
      *(undefined2 *)(iVar11 + 0x12) = 0x1f;
      (**(code **)(*DAT_803dd6cc + 0xc))(0x1e,1);
      *(undefined *)(iVar11 + 0x1a) = 1;
      param_9[3] = param_9[3] | 0x4000;
      break;
    case 6:
      *(undefined *)(iVar11 + 0x1a) = 3;
      break;
    case 7:
      *(undefined *)(iVar11 + 0x1a) = 6;
      *(undefined2 *)(iVar11 + 0x12) = 0x23;
      (**(code **)(*DAT_803dd6cc + 8))(0x1e,1);
    }
  }
  else {
    *(short *)(iVar11 + 0x12) =
         (short)(int)((float)((double)CONCAT44(0x43300000,uVar5) - DOUBLE_803e5b18) - lbl_803DC074
                     );
    if ((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar11 + 0x12) ^ 0x80000000) - dVar3) <=
        fVar4) {
      *(undefined2 *)(iVar11 + 0x12) = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c3a9c
 * EN v1.0 Address: 0x801C3A9C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801C3ABC
 * EN v1.1 Size: 288b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c3a9c(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801c3aa0
 * EN v1.0 Address: 0x801C3AA0
 * EN v1.0 Size: 96b
 * EN v1.1 Address: 0x801C3BDC
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c3aa0(int param_1)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(uint *)(iVar1 + 0x140) != 0) {
    FUN_80017620(*(uint *)(iVar1 + 0x140));
    *(undefined4 *)(iVar1 + 0x140) = 0;
    *(undefined *)(iVar1 + 0x144) = 0;
  }
  (**(code **)(*DAT_803dd6d4 + 0x24))(iVar1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c3b00
 * EN v1.0 Address: 0x801C3B00
 * EN v1.0 Size: 128b
 * EN v1.1 Address: 0x801C3C38
 * EN v1.1 Size: 136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c3b00(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (visible != 0) {
    FUN_8003b818(param_1);
    if (*(char *)(iVar1 + 0x144) == '\0') {
      FUN_8008111c((double)lbl_803E5B30,(double)lbl_803E5B30,param_1,7,(int *)0x0);
    }
    else {
      FUN_8008111c((double)lbl_803E5B30,(double)lbl_803E5B30,param_1,7,*(int **)(iVar1 + 0x140))
      ;
    }
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void dfsh_shrine_hitDetect(void) {}
void dfsh_shrine_release(void) {}
void dfsh_shrine_initialise(void) {}

extern void fn_801C2C68(int p1, int p2, void *p3);
extern int mapGetDirIdx(int id);
extern void unlockLevel(int idx, int a, int b);
extern void *objCreateLight(int *obj, int v);
extern f32 lbl_803E4E8C;

typedef struct DfshShrineFlags {
    u8 openedBySequence : 1;
    u8 unused1 : 1;
    u8 unused2 : 1;
    u8 unused3 : 1;
    u8 unused4 : 1;
    u8 unused5 : 1;
    u8 unused6 : 1;
    u8 unused7 : 1;
} DfshShrineFlags;

#pragma scheduling off
#pragma peephole off
void dfsh_shrine_init(int *obj, u8 *init) {
    u8 *sub;
    DfshShrineFlags *flags;

    sub = *(u8**)((char*)obj + 0xb8);
    flags = (DfshShrineFlags *)(sub + 0x1c);
    *(s16*)obj = (s16)((s8)init[0x18] << 8);
    *(s16*)(sub + 0x10) = 0xa;
    if (*(s16*)(init + 0x1a) > 0) {
        *(s16*)(sub + 0x10) = (s16)((s32)*(s16*)(init + 0x1a) >> 8);
    }
    sub[0x1a] = 4;
    flags->openedBySequence = 0;
    *(s16*)(sub + 0x12) = 0;
    *(void**)((char*)obj + 0xbc) = (void*)&fn_801C2C68;
    ObjMsg_AllocQueue(obj, 4);
    GameBit_Set(0x129, 1);
    sub[0x1b] = 0;
    *(f32*)(sub + 4) = lbl_803E4E8C;
    unlockLevel(mapGetDirIdx(0x1f), 1, 0);
    if (*(void**)sub == NULL) {
        *(int*)sub = (int)objCreateLight(NULL, 1);
    }
    *(int*)((char*)obj + 0xf4) = 1;
    GameBit_Set(0xe70, 1);
    GameBit_Set(0xefa, 1);
}
#pragma peephole reset
#pragma scheduling reset
void SpiritPrize_hitDetect(void) {}
void SpiritPrize_release(void) {}
void SpiritPrize_initialise(void) {}

extern void *gObjectTriggerInterface;
extern void ModelLightStruct_free(void *light);

#pragma scheduling off
#pragma peephole off
void SpiritPrize_free(int obj)
{
    u8 *state;
    void *light;

    state = *(u8 **)(obj + 0xb8);
    light = *(void **)(state + 0x140);
    if (light != NULL) {
        ModelLightStruct_free(light);
        *(void **)(state + 0x140) = NULL;
        state[0x144] = 0;
    }
    ((void (*)(u8 *))((void **)*(int *)gObjectTriggerInterface)[9])(state);
}
#pragma peephole reset
#pragma scheduling reset

extern void *objCreateLight(int *obj, int v);
extern void modelLightStruct_setField50(void *light, int v);
extern void modelLightStruct_setColorsA8AC(void *light, int a, int b, int c, int d);
extern void lightDistAttenFn_8001dc38(void *light, f32 a, f32 b);
extern f32 lbl_803E4E98;
extern f32 lbl_803E4EB0;
extern f32 lbl_803E4EB4;

#pragma scheduling off
#pragma peephole off
void SpiritPrize_init(int *obj, u8 *init) {
    u8 *sub;

    sub = *(u8**)((char*)obj + 0xb8);
    if (*(u32*)(init + 0x14) == 0x4ca62) return;
    *(s16*)(sub + 0x6a) = *(s16*)(init + 0x1a);
    *(s16*)(sub + 0x6e) = -1;
    *(f32*)(sub + 0x24) = lbl_803E4E98 / (lbl_803E4E98 + (f32)(u32)init[0x24]);
    *(int*)(sub + 0x28) = -1;
    if (*(int*)((char*)obj + 0xf4) == 0) {
        if (*(s16*)(init + 0x18) != 1) {
            ((void(*)(u8*))((void**)*(int*)gObjectTriggerInterface)[7])(sub);
            *(int*)((char*)obj + 0xf4) = *(s16*)(init + 0x18) + 1;
        }
    } else {
        if (*(s16*)(init + 0x18) != *(int*)((char*)obj + 0xf4) - 1) {
            ((void(*)(u8*))((void**)*(int*)gObjectTriggerInterface)[9])(sub);
            if (*(s16*)(init + 0x18) != -1) {
                ((void(*)(u8*, u8*))((void**)*(int*)gObjectTriggerInterface)[7])(sub, init);
            }
            *(int*)((char*)obj + 0xf4) = *(s16*)(init + 0x18) + 1;
        }
    }
    if (*(s16*)((char*)obj + 0x46) != 0x1d9) {
        sub[0x144] = 1;
    }
    if (*(int*)(sub + 0x140) == 0) {
        *(int*)(sub + 0x140) = (int)objCreateLight(sub[0x144] != 0 ? NULL : obj, 1);
        if (*(int*)(sub + 0x140) != 0) {
            modelLightStruct_setField50(*(void**)(sub + 0x140), 2);
            modelLightStruct_setColorsA8AC(*(void**)(sub + 0x140), 0x96, 0x32, 0xff, 0xff);
            lightDistAttenFn_8001dc38(*(void**)(sub + 0x140), lbl_803E4EB0, lbl_803E4EB4);
        }
    }
    *(u8*)((char*)obj + 0x36) = 0;
    *(u8*)((char*)obj + 0x37) = 0;
    *(f32*)(sub + 0x148) = (f32)(s32)randomGetRange(0xb4, 0xf0);
}
#pragma peephole reset
#pragma scheduling reset
void dfsh_objcreator_free(void) {}
void dfsh_objcreator_hitDetect(void) {}

/* 8b "li r3, N; blr" returners. */
int SpiritPrize_getExtraSize(void) { return 0x14c; }
int SpiritPrize_getObjectTypeId(void) { return 0x8; }
int dfsh_objcreator_getExtraSize(void) { return 0x4; }
int dfsh_objcreator_getObjectTypeId(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4EB8;
#pragma peephole off
void dfsh_objcreator_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4EB8); }
#pragma peephole reset

#pragma scheduling off
#pragma peephole off
void SpiritPrize_render(int *obj, int p2, int p3, int p4, int p5, s8 visible) {
    u8 *sub;
    s32 v;
    sub = *(u8**)((char*)obj + 0xb8);
    v = visible;
    if (v != 0) {
        objRenderFn_8003b8f4(lbl_803E4E98);
        if (sub[0x144] != 0) {
            objParticleFn_80099d84(obj, 7, *(int*)(sub + 0x140), lbl_803E4E98, lbl_803E4E98);
        } else {
            objParticleFn_80099d84(obj, 7, 0, lbl_803E4E98, lbl_803E4E98);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
