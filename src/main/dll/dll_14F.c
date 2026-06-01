#include "ghidra_import.h"
#include "main/dll/dll_14F.h"
#include "main/objanim.h"

#define SFXen_riverloop11 0x4c
#define SFXen_trpcls_c 0x4d
#define SFXen_generic_placeobj 0x4e
#define SFXen_lrope_powerdown 0x5e

extern bool FUN_800067f0();
extern bool FUN_800067f8();
extern undefined4 FUN_8000680c();
extern undefined8 FUN_80006824();
extern undefined4 FUN_80006a10();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern double FUN_80017708();
extern undefined4 FUN_80017710();
extern double FUN_80017714();
extern undefined4 FUN_8001771c();
extern uint FUN_80017730();
extern undefined4 FUN_80017748();
extern u32 randomGetRange(int min, int max);
extern void mm_free(void *ptr);
extern u32 GameBit_Get(int eventId);
extern void GameBit_Set(int eventId,int value);
extern undefined4 FUN_80017814();
extern undefined8 FUN_80017a28();
extern undefined4 FUN_80017a30();
extern byte FUN_80017a34();
extern undefined4 FUN_80017a3c();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern void *getTrickyObject(void);
extern void *Obj_GetPlayerObject(void);
extern void Obj_StartModelFadeIn(int obj,int frames);
extern u8 Obj_IsLoadingLocked(void);
extern void *Obj_AllocObjectSetup(int extraSize,int objectId);
extern int Obj_SetupObject(void *setup,int mode,int mapLayer,int objIndex,void *parent);
extern undefined4 ObjHits_ClearHitVolumes();
extern undefined8 ObjHits_DisableObject();
extern int ObjHits_IsObjectEnabled();
extern undefined4 ObjHits_RecordObjectHit();
extern int ObjHits_GetPriorityHitWithPosition();
extern int ObjHits_GetPriorityHit();
extern undefined4 ObjGroup_FindNearestObject();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 ObjMsg_AllocQueue();
extern undefined8 ObjLink_DetachChild();
extern undefined4 ObjLink_AttachChild();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800400b0();
extern int FUN_800575b4();
extern int FUN_800620e8();
extern int FUN_800632f4();
extern f32 Vec_xzDistance(f32 *a,f32 *b);
extern f32 vec3f_distanceSquared(f32 *a,f32 *b);
extern undefined4 FUN_80081120();
extern void objLightFn_8009a1dc(int obj,f32 scale,void *pos,int count,int param_5);
extern int FUN_800d9de0();
extern bool FUN_800da5e8();
extern undefined4 FUN_800db110();
extern uint FUN_800db47c();
extern int fn_800DBCFC(f32 *pos,int param_2);
extern int getPatchGroup(f32 *pos,int patchGroup);
extern int cMenuGetSelectedItem(void);
extern int FUN_8012efc4();
extern int FUN_801365a0();
extern int fn_80138F84(int tricky);
extern undefined4 FUN_801816f8();
extern void fn_801816F8(int obj,int param_2,u8 *state);
extern undefined4 FUN_80286838();
extern undefined8 FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern uint FUN_80294c78();
extern byte FUN_80294ca8();
extern uint countLeadingZeros();
extern int Sfx_IsPlayingFromObject(int obj,u16 sfxId);
extern void Sfx_PlayFromObject(int obj,u16 sfxId);
extern void Obj_SetModelColorFadeRecursive(int obj,int frames,int red,int green,int blue,int startAtHalf);
extern void objRenderFn_80041018(int *obj);

extern undefined4 DAT_803dc070;
extern int lbl_803DBDA0;
extern undefined4 DAT_803dca00;
extern undefined4 DAT_803dca08;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd71c;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803e4580;
extern f64 DOUBLE_803e44f8;
extern f64 DOUBLE_803e4500;
extern f64 DOUBLE_803e4570;
extern f64 DOUBLE_803e45b0;
extern f64 DOUBLE_803e45b8;
extern f32 lbl_803DC074;
extern f32 lbl_803DBDA4;
extern f32 lbl_803DBDA8;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803DCA0C;
extern f32 lbl_803DCA10;
extern f32 lbl_803DDA58;
extern f32 lbl_803DDA5C;
extern f32 lbl_803E44EC;
extern f32 lbl_803E44F0;
extern f32 lbl_803E44F4;
extern f32 lbl_803E4508;
extern f32 lbl_803E450C;
extern f32 lbl_803E4510;
extern f32 lbl_803E4518;
extern f32 lbl_803E451C;
extern f32 lbl_803E4524;
extern f32 lbl_803E4528;
extern f32 lbl_803E452C;
extern f32 lbl_803E4530;
extern f32 lbl_803E4538;
extern f32 lbl_803E4540;
extern f32 lbl_803E4548;
extern f32 lbl_803E4550;
extern f32 lbl_803E4554;
extern f32 lbl_803E4558;
extern f32 lbl_803E455C;
extern f32 lbl_803E4560;
extern f32 lbl_803E4564;
extern f32 lbl_803E4568;
extern f32 lbl_803E456C;
extern f32 lbl_803E4578;
extern f32 lbl_803E4584;
extern f32 lbl_803E4588;
extern f32 lbl_803E458C;
extern f32 lbl_803E4590;
extern f32 lbl_803E4594;
extern f32 lbl_803E4598;
extern f32 lbl_803E459C;
extern f32 lbl_803E45A0;
extern f32 lbl_803E45A4;
extern f32 lbl_803E45A8;
extern f32 lbl_803E45AC;
extern f32 lbl_803E45C0;
extern f32 lbl_803E45D0;
extern f32 lbl_803E38A0;
extern f32 lbl_803E38A8;
extern f32 lbl_803E3934;
extern f32 lbl_803E3938;
extern void *gRomCurveInterface;
extern int ViewFrustum_IsSphereVisible(f32 *pos,f32 radius);

/*
 * --INFO--
 *
 * Function: fn_8017F4F4
 * EN v1.0 Address: 0x8017F4F4
 * EN v1.0 Size: 760b
 * EN v1.1 Address: 0x8017F548
 * EN v1.1 Size: 836b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8017F4F4(undefined2 *param_1)
{
  byte bVar1;
  undefined4 uVar2;
  uint uVar3;
  int iVar4;
  byte *pbVar5;
  int iVar6;
  float local_18 [3];
  
  local_18[0] = lbl_803E44EC;
  iVar6 = *(int *)(param_1 + 0x26);
  pbVar5 = *(byte **)(param_1 + 0x5c);
  if (*(int *)(pbVar5 + 4) == 0) {
    uVar2 = ObjGroup_FindNearestObject((uint)*(byte *)(iVar6 + 0x21),param_1,local_18);
    *(undefined4 *)(pbVar5 + 4) = uVar2;
    if (*(int *)(pbVar5 + 4) == 0) {
      return;
    }
    if ((int)*(short *)(iVar6 + 0x1a) == 0xffffffff) {
      pbVar5[1] = 0;
    }
    else {
      uVar3 = FUN_80017690((int)*(short *)(iVar6 + 0x1a));
      pbVar5[1] = (byte)uVar3;
    }
    if ((pbVar5[1] == 0) || (*(short *)(iVar6 + 0x1e) == -1)) {
      *pbVar5 = 2;
    }
    else {
      *pbVar5 = 1;
    }
  }
  *(undefined4 *)(param_1 + 6) = *(undefined4 *)(*(int *)(pbVar5 + 4) + 0xc);
  *(undefined4 *)(param_1 + 8) = *(undefined4 *)(*(int *)(pbVar5 + 4) + 0x10);
  *(undefined4 *)(param_1 + 10) = *(undefined4 *)(*(int *)(pbVar5 + 4) + 0x14);
  *param_1 = **(undefined2 **)(pbVar5 + 4);
  param_1[2] = *(undefined2 *)(*(int *)(pbVar5 + 4) + 4);
  param_1[1] = *(undefined2 *)(*(int *)(pbVar5 + 4) + 2);
  bVar1 = *pbVar5;
  if (bVar1 == 3) {
    uVar3 = FUN_80017690((int)*(short *)(iVar6 + 0x18));
    if (uVar3 != 0) {
      *pbVar5 = 2;
    }
  }
  else if (bVar1 < 3) {
    if (bVar1 == 1) {
      *(byte *)(*(int *)(pbVar5 + 4) + 0xaf) = *(byte *)(*(int *)(pbVar5 + 4) + 0xaf) & 0xdf;
      *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
      (**(code **)(*DAT_803dd6d4 + 0x54))(param_1,(int)*(short *)(iVar6 + 0x1e));
      (**(code **)(*DAT_803dd6d4 + 0x48))
                (*(undefined *)(iVar6 + 0x22),param_1,*(undefined *)(iVar6 + 0x20));
      *pbVar5 = 4;
    }
    else if (bVar1 != 0) {
      if ((pbVar5[1] == 0) || ((*(byte *)(iVar6 + 0x23) & 1) != 0)) {
        if (((int)*(short *)(iVar6 + 0x18) == 0xffffffff) ||
           (uVar3 = FUN_80017690((int)*(short *)(iVar6 + 0x18)), uVar3 != 0)) {
          if (((*(byte *)((int)param_1 + 0xaf) & 1) == 0) ||
             ((*(short *)(iVar6 + 0x1c) != -1 &&
              (iVar4 = (**(code **)(*DAT_803dd6e8 + 0x20))(), iVar4 == 0)))) {
            *(byte *)(*(int *)(pbVar5 + 4) + 0xaf) = *(byte *)(*(int *)(pbVar5 + 4) + 0xaf) | 0x20;
            *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) & 0xf7;
          }
          else {
            if ((*(byte *)(iVar6 + 0x23) & 2) != 0) {
              FUN_80017698((int)*(short *)(iVar6 + 0x18),0);
            }
            if ((int)*(short *)(iVar6 + 0x1a) != 0xffffffff) {
              FUN_80017698((int)*(short *)(iVar6 + 0x1a),1);
            }
            *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
            pbVar5[1] = 1;
            (**(code **)(*DAT_803dd6d4 + 0x48))(*(undefined *)(iVar6 + 0x22),param_1,0xffffffff);
          }
        }
        else {
          *(byte *)(*(int *)(pbVar5 + 4) + 0xaf) = *(byte *)(*(int *)(pbVar5 + 4) + 0xaf) & 0xdf;
          *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
          *pbVar5 = 3;
        }
      }
      else {
        *(byte *)(*(int *)(pbVar5 + 4) + 0xaf) = *(byte *)(*(int *)(pbVar5 + 4) + 0xaf) & 0xdf;
        *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
        *pbVar5 = 4;
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: fn_8017F7B8
 * EN v1.0 Address: 0x8017F7B8
 * EN v1.0 Size: 272b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8017F7B8(int obj,int objectId)
{
  int mapData;
  int *state;
  u8 *setup;
  int childObj;

  mapData = *(int *)(obj + 0x4c);
  state = *(int **)(obj + 0xb8);
  if (Obj_IsLoadingLocked() != 0) {
    setup = Obj_AllocObjectSetup(0x30,objectId);
    setup[0x1a] = 0x14;
    *(s16 *)(setup + 0x2c) = -1;
    *(s16 *)(setup + 0x1c) = -1;
    *(u32 *)(setup + 0x08) = *(u32 *)(obj + 0x0c);
    *(u32 *)(setup + 0x0c) = *(u32 *)(obj + 0x10);
    *(u32 *)(setup + 0x10) = *(u32 *)(obj + 0x14);
    *(s16 *)(setup + 0x24) = -1;
    setup[0x04] = *(u8 *)(mapData + 0x04);
    setup[0x06] = *(u8 *)(mapData + 0x06);
    setup[0x05] = *(u8 *)(mapData + 0x05);
    setup[0x07] = *(u8 *)(mapData + 0x07) - 0xf;
    childObj = Obj_SetupObject(setup,5,(s8)*(u8 *)(obj + 0xac),-1,*(void **)(obj + 0x30));
    if (childObj == 0) {
      mm_free(setup);
      *state = 0;
    }
    else {
      ObjLink_AttachChild(obj,childObj,0);
      *state = childObj;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017f7ec
 * EN v1.0 Address: 0x8017F7EC
 * EN v1.0 Size: 548b
 * EN v1.1 Address: 0x8017F88C
 * EN v1.1 Size: 448b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017f7ec(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,undefined4 param_10,int *param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  uint uVar1;
  int iVar2;
  double dVar3;
  double dVar4;
  
  FUN_80017a98();
  FUN_8000680c(param_9,0x40);
  iVar2 = *param_11;
  if (((iVar2 != 0) && (*(int *)(iVar2 + 0xc4) != 0)) &&
     (lbl_803E4508 <= *(float *)(param_9 + 0x98))) {
    *param_11 = 0;
    ObjLink_DetachChild(param_9,iVar2);
    uVar1 = randomGetRange(0x27,0x2c);
    dVar4 = (double)((f32)(s32)(uVar1) /
                    lbl_803E450C);
    uVar1 = FUN_80017730();
    randomGetRange((uVar1 & 0xffff) - 0x1000,(uVar1 & 0xffff) + 0x1000);
    dVar3 = (double)FUN_80293f90();
    *(float *)(iVar2 + 0x24) = (float)(dVar4 * dVar3);
    param_2 = (double)lbl_803E4510;
    dVar3 = (double)FUN_80294964();
    *(float *)(iVar2 + 0x2c) = (float)(dVar4 * dVar3);
    FUN_80006824(param_9,SFXen_lrope_powerdown);
  }
  if (lbl_803E44F0 <= *(float *)(param_9 + 0x98)) {
    *(undefined *)((int)param_11 + 0xf) = 2;
    param_11[2] = (int)lbl_803E4518;
    ObjAnim_SetCurrentMove((int)param_9,2,lbl_803E44F4,0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: MagicPlant_update
 * EN v1.0 Address: 0x8017FA10
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017FA4C
 * EN v1.1 Size: 708b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void MagicPlant_update(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,undefined4 param_10,int param_11)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8017fa14
 * EN v1.0 Address: 0x8017FA14
 * EN v1.0 Size: 404b
 * EN v1.1 Address: 0x8017FD10
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017fa14(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined2 param_10)
{
  uint uVar1;
  undefined2 *puVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int *piVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_9 + 0x4c);
  piVar3 = *(int **)(param_9 + 0xb8);
  uVar1 = FUN_80017ae8();
  if ((uVar1 & 0xff) != 0) {
    puVar2 = FUN_80017aa4(0x30,param_10);
    *(undefined *)(puVar2 + 0xd) = 0x14;
    puVar2[0x16] = 0xffff;
    puVar2[0xe] = 0xffff;
    *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(param_9 + 0xc);
    *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(param_9 + 0x10);
    *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(param_9 + 0x14);
    puVar2[0x12] = 0xffff;
    *(undefined *)(puVar2 + 2) = *(undefined *)(iVar4 + 4);
    *(undefined *)(puVar2 + 3) = *(undefined *)(iVar4 + 6);
    *(undefined *)((int)puVar2 + 5) = *(undefined *)(iVar4 + 5);
    *(char *)((int)puVar2 + 7) = *(char *)(iVar4 + 7) + -0xf;
    iVar4 = FUN_80017ae4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,5,
                         *(undefined *)(param_9 + 0xac),0xffffffff,*(uint **)(param_9 + 0x30),in_r8,
                         in_r9,in_r10);
    if (iVar4 == 0) {
      FUN_80017814((uint)puVar2);
      *piVar3 = 0;
    }
    else {
      ObjLink_AttachChild(param_9,iVar4,0);
      *piVar3 = iVar4;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017fba8
 * EN v1.0 Address: 0x8017FBA8
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x8017FE20
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8017fba8(void)
{
  (**(code **)(*DAT_803dd6d0 + 0x4c))();
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8017fbe0
 * EN v1.0 Address: 0x8017FBE0
 * EN v1.0 Size: 236b
 * EN v1.1 Address: 0x8017FE70
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017fbe0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  int *piVar1;
  undefined8 uVar2;
  
  piVar1 = *(int **)(param_9 + 0xb8);
  ObjGroup_RemoveObject(param_9,0x34);
  ObjGroup_RemoveObject(param_9,0x3e);
  if ((*(char *)(param_9 + 0xeb) != '\0') && (uVar2 = ObjLink_DetachChild(param_9,*piVar1), param_10 == 0))
  {
    FUN_80017ac8(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*piVar1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017fccc
 * EN v1.0 Address: 0x8017FCCC
 * EN v1.0 Size: 116b
 * EN v1.1 Address: 0x8017FEEC
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017fccc(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  int iVar1;
  int *piVar2;
  
  piVar2 = *(int **)(param_1 + 0xb8);
  if (visible != 0) {
    FUN_8003b818(param_1);
    iVar1 = *piVar2;
    if ((iVar1 != 0) && (*(int *)(iVar1 + 0xc4) != 0)) {
      ObjPath_GetPointWorldPosition(param_1,0,(float *)(iVar1 + 0xc),(undefined4 *)(iVar1 + 0x10),
                   (float *)(iVar1 + 0x14),0);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017fd40
 * EN v1.0 Address: 0x8017FD40
 * EN v1.0 Size: 1888b
 * EN v1.1 Address: 0x8017FF68
 * EN v1.1 Size: 884b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017fd40(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  char cVar2;
  float fVar3;
  byte bVar6;
  int iVar4;
  uint uVar5;
  int iVar7;
  int *piVar8;
  undefined8 extraout_f1;
  double dVar9;
  int iStack_48;
  uint uStack_44;
  undefined4 uStack_40;
  undefined auStack_3c [12];
  float local_30;
  undefined4 uStack_2c;
  float local_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  
  iVar7 = *(int *)(param_9 + 0x26);
  piVar8 = *(int **)(param_9 + 0x5c);
  if ((*piVar8 == 0) || (*(char *)((int)param_9 + 0xeb) != '\0')) {
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) | 8;
    bVar6 = FUN_80017a34((int)param_9);
    if (bVar6 == 0) {
      cVar2 = *(char *)((int)piVar8 + 0xf);
      if (cVar2 == '\x02') {
        if (lbl_803E44F0 <= *(float *)(param_9 + 0x4c)) {
          iVar7 = (uint)*(byte *)(param_9 + 0x1b) + (uint)DAT_803dc070 * -2;
          if (iVar7 < 0) {
            iVar7 = 0;
            *(undefined *)((int)piVar8 + 0xf) = 3;
            fVar1 = lbl_803E44F4;
            dVar9 = (double)lbl_803E44F4;
            piVar8[1] = (int)lbl_803E44F4;
            piVar8[2] = (int)fVar1;
            ObjAnim_SetCurrentMove((int)param_9,0,(float)dVar9,0);
            ObjAnim_SetMoveProgress((double)lbl_803E44F4,(ObjAnimComponent *)param_9);
          }
          *(char *)(param_9 + 0x1b) = (char)iVar7;
        }
        *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) =
             *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) & ~1;
      }
      else if (cVar2 < '\x02') {
        if (cVar2 == '\0') {
          iVar4 = (**(code **)(*DAT_803dd72c + 0x68))(*(undefined4 *)(iVar7 + 0x14));
          if (iVar4 == 0) {
            dVar9 = (double)(**(code **)(*DAT_803dd72c + 0x6c))(*(undefined4 *)(iVar7 + 0x14));
            param_2 = DOUBLE_803e44f8;
            uStack_1c = (uint)*(ushort *)(iVar7 + 0x18);
            if (uStack_1c < 100) {
              uStack_1c = 100;
            }
            uStack_1c = uStack_1c ^ 0x80000000;
            local_20 = 0x43300000;
            fVar1 = (float)(dVar9 / (f64)(f32)(s32)uStack_1c);
            fVar3 = lbl_803E44F0;
            if ((fVar1 <= lbl_803E44F0) && (fVar3 = fVar1, fVar1 < lbl_803E44F4)) {
              fVar3 = lbl_803E44F4;
            }
            piVar8[1] = (int)(lbl_803E44F0 - fVar3);
          }
          else {
            FUN_8017fa14(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (int)param_9,
                         *(undefined2 *)(&DAT_803dca00 + (*(byte *)(iVar7 + 0x1b) & 3) * 2));
            *(undefined *)((int)piVar8 + 0xf) = 1;
            uVar5 = randomGetRange(300,600);
            *(short *)(piVar8 + 3) = (short)uVar5;
          }
          if (param_9[0x50] != 0) {
            ObjAnim_SetCurrentMove((int)param_9,0,(float)piVar8[1],0);
          }
          ObjAnim_SetMoveProgress((double)(float)piVar8[1],(ObjAnimComponent *)param_9);
        }
        else if (-1 < cVar2) {
          MagicPlant_update(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar7
                       ,(int)piVar8);
        }
      }
      else if (cVar2 == '\x04') {
        FUN_8017f7ec(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)param_9,
                     iVar7,piVar8,param_12,param_13,param_14,param_15,param_16);
      }
      else if (cVar2 < '\x04') {
        uVar5 = (uint)*(byte *)(param_9 + 0x1b) + (uint)DAT_803dc070;
        if (0xfe < uVar5) {
          uVar5 = 0xff;
          *(undefined *)((int)piVar8 + 0xf) = 0;
          uStack_1c = (uint)*(ushort *)(iVar7 + 0x18);
          local_20 = 0x43300000;
          (**(code **)(*DAT_803dd72c + 100))
                    ((double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e4500),
                     *(undefined4 *)(iVar7 + 0x14));
        }
        *(char *)(param_9 + 0x1b) = (char)uVar5;
        *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) =
             *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) | 1;
      }
      ObjAnim_AdvanceCurrentMove((double)(float)piVar8[2],(double)lbl_803DC074,(int)param_9,
                                 (ObjAnimEventList *)0x0);
    }
    else {
      iVar7 = ObjHits_GetPriorityHitWithPosition((int)param_9,&uStack_40,&iStack_48,&uStack_44,&local_30,&uStack_2c,
                           local_28);
      if ((iVar7 != 0) && (iVar7 != 0x10)) {
        local_30 = local_30 + lbl_803DDA58;
        local_28[0] = local_28[0] + lbl_803DDA5C;
        FUN_80081120(param_9,auStack_3c,1,(int *)0x0);
        FUN_80006824((uint)param_9,0x47b);
        FUN_80017a30((int)param_9);
      }
    }
  }
  else {
    *piVar8 = 0;
    FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801804a0
 * EN v1.0 Address: 0x801804A0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801802DC
 * EN v1.1 Size: 392b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801804a0(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801804a4
 * EN v1.0 Address: 0x801804A4
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x80180464
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801804a4(int param_1)
{
  if (*(char *)(*(int *)(param_1 + 0xb8) + 1) != '\0') {
    ObjGroup_RemoveObject(param_1,0x4b);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801804d8
 * EN v1.0 Address: 0x801804D8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801804A0
 * EN v1.1 Size: 136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801804d8(int param_1,undefined4 param_2,byte *param_3,int param_4,int param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801804dc
 * EN v1.0 Address: 0x801804DC
 * EN v1.0 Size: 548b
 * EN v1.1 Address: 0x80180528
 * EN v1.1 Size: 620b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801804dc(undefined4 param_1,undefined4 param_2,byte *param_3,int param_4,int param_5)
{
  uint uVar1;
  int iVar2;
  byte bVar7;
  int *piVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  byte *pbVar8;
  byte *pbVar9;
  undefined8 uVar10;
  int local_28 [10];
  
  uVar10 = FUN_8028683c();
  iVar4 = (int)((ulonglong)uVar10 >> 0x20);
  pbVar8 = (byte *)uVar10;
  uVar1 = FUN_80017690(0x4e5);
  if ((uVar1 != 0) && (iVar2 = FUN_80017a90(), iVar2 != 0)) {
    if (*pbVar8 == 0) {
      bVar7 = FUN_800db47c((float *)(iVar4 + 0xc),(undefined *)0x0);
      *pbVar8 = bVar7;
      if (*pbVar8 == 0) goto LAB_80180758;
      piVar3 = (int *)(**(code **)(*DAT_803dd71c + 0x10))(local_28);
      param_3 = pbVar8;
      for (param_4 = 0; param_4 < local_28[0]; param_4 = param_4 + 1) {
        iVar2 = *piVar3;
        if ((*(char *)(iVar2 + 0x19) == '$') && (*(char *)(iVar2 + 3) == '\0')) {
          param_5 = 0;
          iVar5 = 4;
          do {
            if (*(byte *)(iVar2 + param_5 + 4) == *pbVar8) {
              *(undefined4 *)(param_3 + 4) = *(undefined4 *)(iVar2 + 0x14);
              param_3 = param_3 + 4;
              break;
            }
            param_5 = param_5 + 1;
            iVar5 = iVar5 + -1;
          } while (iVar5 != 0);
        }
        piVar3 = piVar3 + 1;
      }
    }
    iVar4 = FUN_800575b4((double)lbl_803E4538,(float *)(iVar4 + 0xc));
    if (iVar4 == 0) {
      iVar4 = FUN_80017a98();
      uVar1 = FUN_800db47c((float *)(iVar4 + 0xc),(undefined *)0x0);
      bVar7 = (byte)param_5;
      if (uVar1 != 0) {
        if (uVar1 == *pbVar8) goto LAB_80180758;
        iVar2 = 0;
        pbVar9 = pbVar8;
        do {
          bVar7 = (byte)param_5;
          if (*(int *)(pbVar9 + 4) == 0) break;
          iVar5 = (**(code **)(*DAT_803dd71c + 0x1c))();
          if ((((iVar5 != 0) &&
               (((int)*(short *)(iVar5 + 0x30) == 0xffffffff ||
                (uVar6 = FUN_80017690((int)*(short *)(iVar5 + 0x30)), uVar6 != 0)))) &&
              (((int)*(short *)(iVar5 + 0x32) == 0xffffffff ||
               (uVar6 = FUN_80017690((int)*(short *)(iVar5 + 0x32)), uVar6 == 0)))) &&
             ((((*(byte *)(iVar5 + 4) == uVar1 || (*(byte *)(iVar5 + 5) == uVar1)) ||
               (*(byte *)(iVar5 + 6) == uVar1)) || (*(byte *)(iVar5 + 7) == uVar1))))
          goto LAB_80180758;
          bVar7 = (byte)param_5;
          pbVar9 = pbVar9 + 4;
          iVar2 = iVar2 + 1;
        } while (iVar2 < 0x18);
      }
      FUN_800db110((float *)(iVar4 + 0xc),(uint)*pbVar8,param_3,param_4,bVar7);
    }
  }
LAB_80180758:
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80180700
 * EN v1.0 Address: 0x80180700
 * EN v1.0 Size: 204b
 * EN v1.1 Address: 0x80180794
 * EN v1.1 Size: 252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80180700(int param_1)
{
  uint uVar1;
  int iVar2;
  char cVar3;
  
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  uVar1 = (uint)*(short *)(*(int *)(param_1 + 0x4c) + 0x1a);
  if ((((uVar1 == 0xffffffff) || (uVar1 = FUN_80017690(uVar1), uVar1 != 0)) &&
      (iVar2 = FUN_80017a90(), iVar2 != 0)) &&
     (cVar3 = (**(code **)(**(int **)(iVar2 + 0x68) + 0x44))(), cVar3 == '\0')) {
    if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
      (**(code **)(**(int **)(iVar2 + 0x68) + 0x28))(iVar2,param_1,1,3);
    }
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    FUN_800400b0();
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801807cc
 * EN v1.0 Address: 0x801807CC
 * EN v1.0 Size: 372b
 * EN v1.1 Address: 0x80180890
 * EN v1.1 Size: 436b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801807cc(int param_1)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  double dVar6;
  
  iVar5 = *(int *)(param_1 + 0x4c);
  iVar2 = FUN_80017a90();
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  if (iVar2 != 0) {
    iVar3 = FUN_801365a0(iVar2);
    uVar1 = countLeadingZeros(param_1 - iVar3);
    if ((uVar1 >> 5 == 0) && ((int)*(short *)(iVar5 + 0x1e) != 0xffffffff)) {
      FUN_80017698((int)*(short *)(iVar5 + 0x1e),0);
    }
    if (((int)*(short *)(iVar5 + 0x20) == 0xffffffff) ||
       (uVar4 = FUN_80017690((int)*(short *)(iVar5 + 0x20)), uVar4 != 0)) {
      if ((uVar1 >> 5 == 0) ||
         (dVar6 = FUN_80017714((float *)(param_1 + 0x18),(float *)(iVar2 + 0x18)),
         (double)lbl_803E4540 <= dVar6)) {
        iVar5 = FUN_8012efc4();
        if (iVar5 == -1) {
          *(undefined *)(*(int *)(*(int *)(param_1 + 0x50) + 0x40) + 0x11) = 0;
        }
        else {
          *(undefined *)(*(int *)(*(int *)(param_1 + 0x50) + 0x40) + 0x11) = 0x10;
        }
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
        if (((*(uint *)(*(int *)(param_1 + 0x50) + 0x44) & 1) != 0) &&
           (*(int *)(param_1 + 0x74) != 0)) {
          FUN_800400b0();
        }
        if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
          (**(code **)(**(int **)(iVar2 + 0x68) + 0x28))(iVar2,param_1,1,3);
        }
      }
      else if ((int)*(short *)(iVar5 + 0x1e) != 0xffffffff) {
        FUN_80017698((int)*(short *)(iVar5 + 0x1e),1);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80180940
 * EN v1.0 Address: 0x80180940
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x80180A44
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80180940(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (((visible != 0) && (*(char *)(*(int *)(param_1 + 0xb8) + 0x1b) != '\0')) &&
     (*(char *)(*(int *)(param_1 + 0xb8) + 0x1c) == '\0')) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80180984
 * EN v1.0 Address: 0x80180984
 * EN v1.0 Size: 136b
 * EN v1.1 Address: 0x80180A94
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80180984(int *param_1)
{
  int iVar1;
  int iVar2;
  int aiStack_60 [22];
  
  iVar2 = param_1[0x2e];
  iVar1 = FUN_800620e8(param_1 + 0x20,param_1 + 3,(float *)0x2,aiStack_60,param_1,8,0xffffffff,0xff,
                       0);
  if (iVar1 != 0) {
    *(undefined *)(iVar2 + 0x1a) = 1;
  }
  param_1[0x20] = param_1[3];
  param_1[0x21] = param_1[4];
  param_1[0x22] = param_1[5];
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80180a0c
 * EN v1.0 Address: 0x80180A0C
 * EN v1.0 Size: 1980b
 * EN v1.1 Address: 0x80180B20
 * EN v1.1 Size: 1764b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80180a0c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  float fVar1;
  ushort *puVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  undefined4 *puVar7;
  int iVar8;
  undefined4 in_r7;
  undefined4 in_r8;
  int in_r9;
  undefined4 in_r10;
  int iVar9;
  float *pfVar10;
  double dVar11;
  undefined8 uVar12;
  double dVar13;
  uint local_48;
  undefined4 *local_44;
  ushort local_40 [4];
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  undefined8 local_28;
  longlong local_20;
  
  puVar2 = (ushort *)FUN_80286840();
  pfVar10 = *(float **)(puVar2 + 0x5c);
  iVar9 = *(int *)(puVar2 + 0x26);
  iVar3 = FUN_80017a98();
  while (iVar4 = ObjMsg_Pop((int)puVar2,&local_48,(uint *)0x0,(uint *)0x0), iVar4 != 0) {
    if (local_48 == 0x7000b) {
      FUN_80006824((uint)puVar2,SFXen_generic_placeobj);
      (**(code **)(*DAT_803dd708 + 8))(puVar2,0x51a,0,1,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(puVar2,0x51a,0,1,0xffffffff,0);
      in_r7 = 0xffffffff;
      in_r8 = 0;
      in_r9 = *DAT_803dd708;
      (**(code **)(in_r9 + 8))(puVar2,0x51a,0,1);
      FUN_80017698((int)*(short *)(pfVar10 + 3),1);
      iVar4 = (**(code **)(*DAT_803dd72c + 0x8c))();
      uVar5 = *(byte *)(iVar4 + 9) + 1;
      if (*(byte *)(iVar4 + 10) < uVar5) {
        uVar5 = (uint)*(byte *)(iVar4 + 10);
      }
      *(char *)(iVar4 + 9) = (char)uVar5;
      *(undefined *)(pfVar10 + 7) = 1;
    }
  }
  if ((*(char *)((int)pfVar10 + 0x1b) == '\0') || (*(char *)(pfVar10 + 7) == '\x01')) {
    if (*(char *)((int)pfVar10 + 0x1b) == '\0') {
      uVar5 = FUN_80017690((int)*(short *)((int)pfVar10 + 0xe));
      *(char *)((int)pfVar10 + 0x1b) = (char)uVar5;
      *(undefined2 *)(pfVar10 + 2) = 0;
    }
  }
  else {
    dVar13 = (double)*(float *)(puVar2 + 0x14);
    if ((double)lbl_803E4550 < dVar13) {
      *(float *)(puVar2 + 0x14) = (float)((double)lbl_803E4554 * (double)lbl_803DC074 + dVar13);
    }
    *(undefined *)((int)pfVar10 + 0x1a) = 0;
    if (-1 < *(char *)((int)pfVar10 + 0x1e)) {
      dVar13 = (double)*(float *)(puVar2 + 8);
      iVar6 = FUN_800632f4((double)*(float *)(puVar2 + 6),dVar13,(double)*(float *)(puVar2 + 10),
                           puVar2,&local_44,0,0);
      param_3 = (double)lbl_803E4558;
      iVar4 = -1;
      iVar8 = 0;
      puVar7 = local_44;
      if (0 < iVar6) {
        do {
          dVar13 = (double)*(float *)*puVar7;
          dVar11 = (double)(float)(dVar13 - (double)*(float *)(puVar2 + 8));
          if (dVar11 < (double)lbl_803E455C) {
            dVar11 = -dVar11;
          }
          if (dVar11 < param_3) {
            iVar4 = iVar8;
            param_3 = dVar11;
          }
          puVar7 = puVar7 + 1;
          iVar8 = iVar8 + 1;
          iVar6 = iVar6 + -1;
        } while (iVar6 != 0);
      }
      if (iVar4 != -1) {
        *(byte *)((int)pfVar10 + 0x1e) = *(byte *)((int)pfVar10 + 0x1e) & 0x7f | 0x80;
        pfVar10[1] = *(float *)local_44[iVar4];
        *(float *)(puVar2 + 0x14) = lbl_803E455C;
      }
      if (-1 < *(char *)((int)pfVar10 + 0x1e)) {
        pfVar10[1] = *(float *)(iVar9 + 0xc);
        *(byte *)((int)pfVar10 + 0x1e) = *(byte *)((int)pfVar10 + 0x1e) & 0x7f | 0x80;
      }
    }
    if (*(float *)(puVar2 + 8) < pfVar10[1]) {
      *(float *)(puVar2 + 8) = pfVar10[1];
      *(float *)(puVar2 + 0x14) = lbl_803E455C;
    }
    if ((*(short *)(pfVar10 + 2) == 0) && (*(short *)((int)pfVar10 + 10) == 0)) {
      dVar13 = (double)lbl_803DC074;
      iVar9 = ObjAnim_AdvanceCurrentMove((double)*pfVar10,dVar13,(int)puVar2,
                                         (ObjAnimEventList *)0x0);
      if ((iVar9 == 0) && (*(char *)((int)pfVar10 + 0x1a) == '\0')) {
        *(float *)(puVar2 + 6) = *(float *)(puVar2 + 0x12) * lbl_803DC074 + *(float *)(puVar2 + 6)
        ;
        dVar13 = (double)*(float *)(puVar2 + 0x16);
        *(float *)(puVar2 + 10) =
             (float)(dVar13 * (double)lbl_803DC074 + (double)*(float *)(puVar2 + 10));
      }
      else {
        FUN_80006824((uint)puVar2,SFXen_riverloop11);
        (**(code **)(*DAT_803dd708 + 8))(puVar2,0x51f,0,2,0xffffffff,0);
        in_r7 = 0xffffffff;
        in_r8 = 0;
        in_r9 = *DAT_803dd708;
        (**(code **)(in_r9 + 8))(puVar2,0x51f,0,2);
        uVar5 = randomGetRange(0,4);
        *(char *)(pfVar10 + 6) = (char)uVar5;
        fVar1 = lbl_803E455C;
        if (*(char *)((int)pfVar10 + 0x1d) == '\0') {
          *(float *)(puVar2 + 0x12) = lbl_803E455C;
          *(float *)(puVar2 + 0x16) = fVar1;
        }
        else {
          *(float *)(puVar2 + 0x12) = lbl_803E4560;
          local_34 = lbl_803E455C;
          *(float *)(puVar2 + 0x16) = lbl_803E455C;
          local_30 = local_34;
          local_2c = local_34;
          local_38 = lbl_803E4548;
          local_40[2] = 0;
          local_40[1] = 0;
          local_40[0] = *puVar2;
          FUN_80017748(local_40,(float *)(puVar2 + 0x12));
        }
        if (*(char *)((int)pfVar10 + 0x19) != '\0') {
          *(undefined2 *)((int)pfVar10 + 10) = 0xfa;
        }
      }
      iVar9 = ObjHits_GetPriorityHit((int)puVar2,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
      if (iVar9 == 0xe) {
        *(undefined *)((int)pfVar10 + 0x19) = 1;
        FUN_80006824((uint)puVar2,SFXen_trpcls_c);
      }
    }
    else {
      if (*(short *)(pfVar10 + 2) != 0) {
        local_28 = (double)(longlong)(int)lbl_803DC074;
        *(short *)(pfVar10 + 2) = *(short *)(pfVar10 + 2) - (short)(int)lbl_803DC074;
        if (*(short *)(pfVar10 + 2) < 1) {
          *(undefined2 *)(pfVar10 + 2) = 0;
        }
      }
      if (*(short *)((int)pfVar10 + 10) != 0) {
        local_28 = (double)(longlong)(int)lbl_803DC074;
        *(short *)((int)pfVar10 + 10) = *(short *)((int)pfVar10 + 10) - (short)(int)lbl_803DC074;
        if (*(short *)((int)pfVar10 + 10) < 1) {
          *(undefined2 *)((int)pfVar10 + 10) = 0;
          *(undefined *)((int)pfVar10 + 0x19) = 0;
        }
      }
    }
    if (*(char *)(pfVar10 + 6) == '\x04') {
      if (*(char *)((int)pfVar10 + 0x1a) != '\0') {
        *puVar2 = *puVar2 + 0x8001;
        *(undefined *)(pfVar10 + 6) = 0;
      }
      param_3 = (double)lbl_803E4564;
      dVar13 = (double)lbl_803DC074;
      local_28 = (double)CONCAT44(0x43300000,(int)(short)*puVar2 ^ 0x80000000);
      iVar9 = (int)(param_3 * dVar13 + (double)(float)(local_28 - DOUBLE_803e4570));
      local_20 = (longlong)iVar9;
      *puVar2 = (ushort)iVar9;
    }
    fVar1 = *(float *)(iVar3 + 0x10) - *(float *)(puVar2 + 8);
    if (fVar1 < lbl_803E455C) {
      fVar1 = -fVar1;
    }
    if (((fVar1 < lbl_803E4568) &&
        (dVar11 = (double)FUN_80017710((float *)(iVar3 + 0x18),(float *)(puVar2 + 0xc)),
        dVar11 < (double)lbl_803E456C)) && (uVar5 = FUN_80294c78(iVar3), uVar5 != 0)) {
      uVar5 = FUN_80017690(0xcc0);
      if (uVar5 == 0) {
        *(undefined2 *)(pfVar10 + 4) = 0xffff;
        uVar12 = ObjHits_DisableObject((int)puVar2);
        ObjMsg_SendToObject(uVar12,dVar13,param_3,param_4,param_5,param_6,param_7,param_8,iVar3,0x7000a,
                     (uint)puVar2,(uint)(pfVar10 + 4),in_r7,in_r8,in_r9,in_r10);
        FUN_80017698(0xcc0,1);
      }
      else {
        iVar3 = (**(code **)(*DAT_803dd72c + 0x8c))();
        if (*(byte *)(iVar3 + 9) < *(byte *)(iVar3 + 10)) {
          FUN_80006824((uint)puVar2,SFXen_generic_placeobj);
          (**(code **)(*DAT_803dd708 + 8))(puVar2,0x51a,0,1,0xffffffff,0);
          (**(code **)(*DAT_803dd708 + 8))(puVar2,0x51a,0,1,0xffffffff,0);
          (**(code **)(*DAT_803dd708 + 8))(puVar2,0x51a,0,1,0xffffffff,0);
          FUN_80017698((int)*(short *)(pfVar10 + 3),1);
          iVar3 = (**(code **)(*DAT_803dd72c + 0x8c))();
          uVar5 = *(byte *)(iVar3 + 9) + 1;
          if (*(byte *)(iVar3 + 10) < uVar5) {
            uVar5 = (uint)*(byte *)(iVar3 + 10);
          }
          *(char *)(iVar3 + 9) = (char)uVar5;
          *(undefined *)(pfVar10 + 7) = 1;
          *(undefined *)(puVar2 + 0x1b) = 1;
        }
      }
      if (*(int *)(puVar2 + 0x2a) != 0) {
        ObjHits_DisableObject((int)puVar2);
      }
    }
    *(float *)(puVar2 + 8) = *(float *)(puVar2 + 8) + *(float *)(puVar2 + 0x14);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801811c8
 * EN v1.0 Address: 0x801811C8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80181204
 * EN v1.1 Size: 292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801811c8(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801811cc
 * EN v1.0 Address: 0x801811CC
 * EN v1.0 Size: 2244b
 * EN v1.1 Address: 0x80181328
 * EN v1.1 Size: 1672b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801811cc(void)
{
  ushort *puVar1;
  int iVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  bool bVar7;
  int iVar6;
  byte bVar8;
  undefined4 uVar9;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar10;
  int iVar11;
  float *pfVar12;
  undefined8 extraout_f1;
  double dVar13;
  undefined8 extraout_f1_00;
  double dVar14;
  double dVar15;
  double in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  double in_f29;
  double dVar16;
  double in_f30;
  double in_f31;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined4 local_68 [2];
  undefined8 local_60;
  undefined4 local_58;
  uint uStack_54;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  puVar1 = (ushort *)FUN_80286838();
  pfVar12 = *(float **)(puVar1 + 0x5c);
  iVar11 = *(int *)(puVar1 + 0x26);
  iVar2 = FUN_80017a98();
  iVar10 = *(int *)(puVar1 + 0x26);
  local_68[0] = DAT_803e4580;
  pfVar12[0x47] = pfVar12[0x47] + lbl_803DC074;
  bVar8 = *(byte *)(pfVar12 + 0x42);
  if (bVar8 == 2) {
LAB_801814d8:
    if (pfVar12[0x47] <= lbl_803E4584) {
      iVar2 = (int)(lbl_803E458C * (pfVar12[0x47] / lbl_803E4584));
      local_60 = (double)(longlong)iVar2;
      *(char *)(puVar1 + 0x1b) = (char)iVar2;
      goto LAB_80181980;
    }
    *(undefined *)(puVar1 + 0x1b) = 0xff;
    *(undefined *)(pfVar12 + 0x42) = 3;
  }
  else {
    if (bVar8 < 2) {
      if (bVar8 == 0) {
        local_60 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar11 + 0x20));
        fVar3 = lbl_803E4584 * (float)(local_60 - DOUBLE_803e45b0);
        if (pfVar12[0x47] < fVar3) goto LAB_80181980;
        pfVar12[0x47] = pfVar12[0x47] - fVar3;
        *(undefined *)(pfVar12 + 0x42) = 1;
      }
      *(undefined4 *)(puVar1 + 6) = *(undefined4 *)(iVar10 + 8);
      *(undefined4 *)(puVar1 + 8) = *(undefined4 *)(iVar10 + 0xc);
      *(undefined4 *)(puVar1 + 10) = *(undefined4 *)(iVar10 + 0x10);
      dVar14 = (double)*(float *)(puVar1 + 8);
      dVar15 = (double)*(float *)(puVar1 + 10);
      (**(code **)(*DAT_803dd71c + 0x14))((double)*(float *)(puVar1 + 6),local_68,1,0xffffffff);
      fVar3 = (float)(**(code **)(*DAT_803dd71c + 0x1c))();
      (**(code **)(*DAT_803dd71c + 0x54))(fVar3,0);
      fVar4 = (float)(**(code **)(*DAT_803dd71c + 0x1c))();
      (**(code **)(*DAT_803dd71c + 0x54))(fVar4,0);
      fVar5 = (float)(**(code **)(*DAT_803dd71c + 0x1c))();
      bVar7 = FUN_800da5e8(extraout_f1,dVar14,dVar15,in_f4,in_f5,in_f6,in_f7,in_f8,pfVar12,fVar3,
                           fVar4,fVar5,in_r7,in_r8,in_r9,in_r10);
      if (bVar7) goto LAB_80181980;
      *(undefined *)(pfVar12 + 0x42) = 2;
      pfVar12[0x45] = lbl_803E4588;
      goto LAB_801814d8;
    }
    if (3 < bVar8) goto LAB_80181980;
  }
  uVar9 = 0;
  iVar6 = ObjHits_GetPriorityHit((int)puVar1,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
  if (iVar6 == 0) {
    bVar8 = FUN_80294ca8(iVar2);
    if (bVar8 != 0) {
      dVar14 = FUN_80017708((float *)(iVar2 + 0xc),(float *)(puVar1 + 6));
      in_f4 = DOUBLE_803e45b0;
      fVar3 = lbl_803E4590;
      uStack_54 = (uint)*(byte *)(iVar11 + 0x23);
      local_60 = (double)CONCAT44(0x43300000,uStack_54);
      local_58 = 0x43300000;
      if (dVar14 < (double)((float)(local_60 - DOUBLE_803e45b0) *
                           (f32)(s32)uStack_54)) {
        uStack_54 = (uint)*(byte *)(iVar10 + 0x19);
        local_58 = 0x43300000;
        pfVar12[0x45] =
             pfVar12[0x45] +
             (lbl_803E4590 * (f32)(s32)uStack_54 *
             lbl_803DC074) / lbl_803E4594;
        if (fVar3 * pfVar12[0x44] < pfVar12[0x45]) {
          pfVar12[0x45] = fVar3 * pfVar12[0x44];
        }
        goto LAB_80181668;
      }
    }
    uStack_54 = randomGetRange(-(uint)*(byte *)(iVar10 + 0x19),(uint)*(byte *)(iVar10 + 0x19) << 1);
    pfVar12[0x45] =
         pfVar12[0x45] +
         ((float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e45b8) * lbl_803DC074) /
         lbl_803E4594;
    if (lbl_803E4588 <= pfVar12[0x45]) {
      if (pfVar12[0x44] < pfVar12[0x45]) {
        pfVar12[0x45] = pfVar12[0x44];
      }
    }
    else {
      pfVar12[0x45] = lbl_803E4588;
    }
  }
  else {
    pfVar12[0x45] = lbl_803E4590 * pfVar12[0x44];
  }
LAB_80181668:
  dVar15 = (double)pfVar12[0x45];
  dVar14 = (double)pfVar12[0x44];
  if ((double)(float)(dVar14 * (double)lbl_803E4598) <= dVar15) {
    if (dVar15 <= (double)(float)((double)(float)((double)lbl_803E45A4 * dVar14) *
                                 (double)lbl_803E4598)) {
      if ((puVar1[0x50] == 1) && (lbl_803E45A8 < pfVar12[0x43])) {
        ObjAnim_SetCurrentMove((int)puVar1,0,lbl_803E4588,0);
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)puVar1,0x3c);
        pfVar12[0x43] = lbl_803E4588;
      }
      pfVar12[0x46] = (lbl_803E45AC * pfVar12[0x45]) / pfVar12[0x44];
    }
    else {
      if ((puVar1[0x50] == 0) && (lbl_803E45A8 < pfVar12[0x43])) {
        ObjAnim_SetCurrentMove((int)puVar1,1,lbl_803E4588,0);
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)puVar1,0x3c);
        pfVar12[0x43] = lbl_803E4588;
      }
      pfVar12[0x46] = lbl_803E45AC;
    }
  }
  else {
    if ((puVar1[0x50] == 0) && (lbl_803E459C < pfVar12[0x43])) {
      ObjAnim_SetCurrentMove((int)puVar1,1,lbl_803E4588,0);
      ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)puVar1,0x3c);
      pfVar12[0x43] = lbl_803E4588;
    }
    pfVar12[0x46] = lbl_803E45A0;
  }
  if (lbl_803E4588 != pfVar12[0x45]) {
    fVar3 = pfVar12[0x45] * lbl_803DC074;
    dVar16 = (double)(fVar3 * fVar3);
    dVar13 = FUN_80017708(pfVar12 + 0x1a,(float *)(puVar1 + 6));
    for (iVar2 = 0; (dVar13 < dVar16 && (iVar2 < 5)); iVar2 = iVar2 + 1) {
      FUN_80006a10((double)lbl_803E4590,pfVar12);
      dVar13 = FUN_80017708(pfVar12 + 0x1a,(float *)(puVar1 + 6));
    }
    if (pfVar12[4] != 0.0) {
      iVar2 = *DAT_803dd71c;
      (**(code **)(iVar2 + 0x54))(pfVar12[0x29],0);
      fVar3 = (float)(**(code **)(*DAT_803dd71c + 0x1c))();
      iVar2 = FUN_800d9de0(extraout_f1_00,dVar14,dVar15,in_f4,in_f5,in_f6,in_f7,in_f8,pfVar12,fVar3,
                           iVar2,uVar9,in_r7,in_r8,in_r9,in_r10);
      if (iVar2 != 0) {
        *(undefined *)(pfVar12 + 0x42) = 0;
        pfVar12[0x47] = lbl_803E4588;
        *(undefined *)(puVar1 + 0x1b) = 0;
        goto LAB_80181980;
      }
    }
    dVar16 = (double)(pfVar12[0x1a] - *(float *)(puVar1 + 6));
    uStack_54 = (uint)*(byte *)(iVar11 + 0x22);
    local_58 = 0x43300000;
    dVar13 = (double)((pfVar12[0x1b] +
                      (f32)(s32)uStack_54) -
                     *(float *)(puVar1 + 8));
    dVar15 = (double)(pfVar12[0x1c] - *(float *)(puVar1 + 10));
    dVar14 = FUN_80293900((double)(float)(dVar15 * dVar15 +
                                         (double)(float)(dVar16 * dVar16 +
                                                        (double)(float)(dVar13 * dVar13))));
    *(float *)(puVar1 + 6) = (float)(dVar16 / dVar14) * pfVar12[0x45] + *(float *)(puVar1 + 6);
    *(float *)(puVar1 + 8) = (float)(dVar13 / dVar14) * pfVar12[0x45] + *(float *)(puVar1 + 8);
    *(float *)(puVar1 + 10) = (float)(dVar15 / dVar14) * pfVar12[0x45] + *(float *)(puVar1 + 10);
    iVar2 = FUN_80017730();
    iVar10 = (int)(short)(ushort)iVar2 - (uint)*puVar1;
    if (0x8000 < iVar10) {
      iVar10 = iVar10 + -0xffff;
    }
    if (iVar10 < -0x8000) {
      iVar10 = iVar10 + 0xffff;
    }
    if (iVar10 < 0x181) {
      if (iVar10 < -0x180) {
        *puVar1 = *puVar1 - 0x180;
      }
      else {
        *puVar1 = (ushort)iVar2;
      }
    }
    else {
      *puVar1 = *puVar1 + 0x180;
    }
  }
  ObjAnim_AdvanceCurrentMove((double)pfVar12[0x46],(double)lbl_803DC074,(int)puVar1,
                             (ObjAnimEventList *)0x0);
  pfVar12[0x43] = pfVar12[0x43] + lbl_803DC074;
LAB_80181980:
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80181a90
 * EN v1.0 Address: 0x80181A90
 * EN v1.0 Size: 192b
 * EN v1.1 Address: 0x801819B0
 * EN v1.1 Size: 120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80181a90(int param_1,int param_2)
{
  double dVar1;
  float fVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  fVar2 = lbl_803E45C0;
  dVar1 = DOUBLE_803e45b0;
  *(float *)(param_1 + 8) =
       *(float *)(*(int *)(param_1 + 0x50) + 4) *
       ((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x18)) - DOUBLE_803e45b0) /
       lbl_803E45C0);
  *(undefined *)(iVar3 + 0x108) = 1;
  *(float *)(iVar3 + 0x110) =
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x19)) - dVar1) / fVar2;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80181b50
 * EN v1.0 Address: 0x80181B50
 * EN v1.0 Size: 756b
 * EN v1.1 Address: 0x80181A28
 * EN v1.1 Size: 552b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80181b50(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11)
{
  float fVar1;
  ushort *puVar2;
  int iVar3;
  bool bVar6;
  int *piVar4;
  ushort uVar5;
  undefined4 uVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  float *pfVar10;
  undefined4 in_r10;
  double dVar11;
  undefined8 uVar12;
  undefined8 uVar13;
  int local_48;
  uint uStack_44;
  int iStack_40;
  int local_3c;
  undefined auStack_38 [12];
  float local_2c;
  undefined4 uStack_28;
  float local_24 [9];
  
  uVar13 = FUN_80286840();
  puVar2 = (ushort *)((ulonglong)uVar13 >> 0x20);
  pfVar10 = local_24;
  iVar3 = ObjHits_GetPriorityHitWithPosition((int)puVar2,&local_3c,&iStack_40,&uStack_44,&local_2c,&uStack_28,pfVar10);
  if (iVar3 != 0) {
    if (iVar3 == 0x10) {
      FUN_80017a3c(puVar2,300);
    }
    else {
      local_2c = local_2c + lbl_803DDA58;
      local_24[0] = local_24[0] + lbl_803DDA5C;
      if (*(char *)(param_11 + 0x20) != '\0') {
        if (iVar3 != 5) {
          FUN_80081120(puVar2,auStack_38,4,(int *)0x0);
          bVar6 = FUN_800067f8(0,0x37e);
          if (!bVar6) {
            FUN_80006824((uint)puVar2,0x37e);
          }
          goto LAB_80181c38;
        }
        piVar4 = ObjGroup_GetObjects(0x10,&local_48);
        for (iVar3 = 0; iVar3 < local_48; iVar3 = iVar3 + 1) {
          uVar5 = ObjHits_IsObjectEnabled(*piVar4);
          if (uVar5 != 0) {
            param_2 = (double)*(float *)(*piVar4 + 0x10);
            if ((((double)*(float *)(puVar2 + 8) < param_2) &&
                (param_2 < (double)(float)((double)*(float *)(puVar2 + 8) + (double)lbl_803DCA10))
                ) && (dVar11 = (double)FUN_80017710((float *)(*piVar4 + 0x18),
                                                    (float *)(puVar2 + 0xc)),
                     dVar11 < (double)lbl_803DCA0C)) {
              ObjHits_RecordObjectHit(*piVar4,local_3c,'\x05',1,0);
            }
          }
          piVar4 = piVar4 + 1;
        }
      }
      FUN_80081120(puVar2,auStack_38,1,(int *)0x0);
      uVar7 = 0;
      uVar8 = 0;
      uVar9 = 1;
      uVar12 = FUN_80017a28(puVar2,0xf,200,0,0,1);
      bVar6 = FUN_800067f8(0,*(short *)(param_11 + 0x10));
      if (!bVar6) {
        uVar12 = FUN_80006824((uint)puVar2,*(ushort *)(param_11 + 0x10));
      }
      *(undefined2 *)(param_11 + 10) = 0x32;
      *(undefined *)(param_11 + 9) = 0;
      FUN_801816f8(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,(int)uVar13
                   ,param_11,uVar7,uVar8,uVar9,pfVar10,in_r10);
      *(byte *)((int)puVar2 + 0xaf) = *(byte *)((int)puVar2 + 0xaf) | 8;
      fVar1 = lbl_803E45D0;
      *(float *)(puVar2 + 0x12) = lbl_803E45D0;
      *(float *)(puVar2 + 0x16) = fVar1;
      ObjHits_ClearHitVolumes((int)puVar2);
      if (DAT_803dca08 != 0) {
        ObjHits_DisableObject((int)puVar2);
      }
    }
  }
LAB_80181c38:
  FUN_8028688c();
  return;
}

/* 8b "li r3, N; blr" returners. */
int MagicPlant_getExtraSize(void) { return 0x10; }
int trickywarp_getExtraSize(void) { return 0x64; }
int duster_getExtraSize(void) { return 0x20; }
int curvefish_getExtraSize(void) { return 0x120; }

/* fn_801804C8: clear bit 0x80 of obj->_b8->_1e, return 0. */
#pragma scheduling off
#pragma peephole off
int fn_801804C8(u8* obj) {
    u8* sub = *(u8**)(obj + 0xb8);
    sub[0x1e] = (u8)(sub[0x1e] & ~0x80);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

/* gCameraInterface: vtable pointer used for state-machine dispatches. */
extern void *gCameraInterface;

/* fn_8017F8C8: vtable[0x13]() with obj passed through implicitly, return 0. */
#pragma scheduling off
int fn_8017F8C8(u8* obj) {
    (*(void (***)(u8*))gCameraInterface)[0x13](obj);
    return 0;
}
#pragma scheduling reset

/* state encode: ((obj->_X)->_Y << shift) | const. */
u32 MagicPlant_getObjectTypeId(int *obj) { return (*((u8*)((int**)obj)[0x4c/4] + 0x1c) << 11) | 0x400; }

/* obj->u16_X |= MASK */
#pragma peephole off
void StayPoint_init(u16 *obj) { u32 v; v = *(u16*)((char*)obj + 0xb0); v |= 0x4000; *(u16*)((char*)obj + 0xb0) = (u16)v; }
#pragma peephole reset

extern void Obj_FreeObject(int obj);
extern void objRenderFn_8003b8f4(int obj, float arg);
extern f32 lbl_803E3858;
extern f32 lbl_803E38B0;

#pragma scheduling off
#pragma peephole off
void MagicPlant_free(int param_1, int param_2) {
  int obj = param_1;
  int *state;
  state = *(int **)(obj + 0xb8);
  ObjGroup_RemoveObject(obj, 0x34);
  ObjGroup_RemoveObject(obj, 0x3e);
  if (*(u8 *)(obj + 0xeb) != 0) {
    ObjLink_DetachChild(obj, *state);
    if (param_2 == 0) {
      Obj_FreeObject(*state);
    }
  }
}
#pragma scheduling reset

#pragma peephole off
#pragma scheduling off
void MagicPlant_render(int obj, int p2, int p3, int p4, int p5, s8 visible) {
  int *state;
  void *s0;
  s32 v;
  state = *(int **)(obj + 0xb8);
  v = visible;
  if (v != 0) {
    objRenderFn_8003b8f4(obj, lbl_803E3858);
    s0 = *(void **)state;
    if (s0 != NULL) {
      if (*(void **)((char *)s0 + 0xc4) != NULL) {
        ObjPath_GetPointWorldPosition(obj, 0, (float *)((char *)s0 + 0xc), (float *)((char *)s0 + 0x10), (float *)((char *)s0 + 0x14), 0);
      }
    }
  }
}
#pragma scheduling reset
#pragma peephole reset

void trickywarp_free(int obj) {
  TrickyWarpState *state = *(TrickyWarpState **)(obj + 0xb8);
  if (state->active != 0) {
    ObjGroup_RemoveObject(obj, 0x4b);
  }
}

typedef struct TrickyWarpCurveEntry {
  u8 pad00[3];
  u8 entryPatchGroup;
  u8 linkPatchGroups[4];
  u8 pad08[0xc];
  u32 nodeId;
  s8 action;
  s8 type;
} TrickyWarpCurveEntry;

typedef struct TrickyWarpCurveNode {
  u8 pad00[4];
  u8 linkPatchGroups[4];
  u8 pad08[0x28];
  s16 requiredGameBit;
  s16 forbiddenGameBit;
} TrickyWarpCurveNode;

int fn_8017FFD0(int obj, TrickyWarpState *state) {
  int curveCount;
  TrickyWarpCurveEntry **curveEntries;
  TrickyWarpCurveEntry *entry;
  TrickyWarpCurveNode *node;
  int *outNodeId;
  int playerObj;
  int playerPatchGroup;
  int i;
  int linkIndex;

  if (GameBit_Get(0x4e5) == 0) {
    return 0;
  }
  if (getTrickyObject() == NULL) {
    return 0;
  }
  if (state->patchGroup == 0) {
    state->patchGroup = (u8)fn_800DBCFC((f32 *)(obj + 0xc),0);
    if (state->patchGroup != 0) {
      curveEntries = (*(TrickyWarpCurveEntry **(**)(int *))(*(int *)gRomCurveInterface + 0x10))(&curveCount);
      outNodeId = state->curveNodeIds;
      for (i = 0; i < curveCount; i++) {
        entry = curveEntries[i];
        if (entry->type == '$' && entry->entryPatchGroup == 0) {
          for (linkIndex = 0; linkIndex < 4; linkIndex++) {
            if (entry->linkPatchGroups[linkIndex] == state->patchGroup) {
              *outNodeId = entry->nodeId;
              outNodeId++;
              break;
            }
          }
        }
      }
    } else {
      return 0;
    }
  }
  if (ViewFrustum_IsSphereVisible((f32 *)(obj + 0xc),lbl_803E38A0) != 0) {
    return 0;
  }
  playerObj = (int)Obj_GetPlayerObject();
  playerPatchGroup = fn_800DBCFC((f32 *)(playerObj + 0xc),0);
  if (playerPatchGroup != 0) {
    if (playerPatchGroup == state->patchGroup) {
      return 1;
    }
    for (i = 0; i < 0x18; i++) {
      if (state->curveNodeIds[i] == 0) {
        break;
      }
      node = (*(TrickyWarpCurveNode *(**)(int))(*(int *)gRomCurveInterface + 0x1c))(state->curveNodeIds[i]);
      if (node != NULL) {
        if (node->requiredGameBit == -1 || GameBit_Get(node->requiredGameBit) != 0) {
          if (node->forbiddenGameBit == -1 || GameBit_Get(node->forbiddenGameBit) == 0) {
            if (node->linkPatchGroups[0] == playerPatchGroup) {
              return 1;
            }
            if (node->linkPatchGroups[1] == playerPatchGroup) {
              return 1;
            }
            if (node->linkPatchGroups[2] == playerPatchGroup) {
              return 1;
            }
            if (node->linkPatchGroups[3] == playerPatchGroup) {
              return 1;
            }
          }
        }
      }
    }
  }
  return getPatchGroup((f32 *)(playerObj + 0xc),state->patchGroup);
}

#pragma peephole off
void trickywarp_init(s16 *obj, u8 *param_2) {
  u32 v;
  v = *(u16 *)((char *)obj + 0xb0);
  v |= 0x4000;
  *(u16 *)((char *)obj + 0xb0) = (u16)v;
  *obj = (s16)((u32)param_2[0x1a] << 8);
}

void trickyguard_init(s16 *obj, u8 *param_2) {
  u32 v;
  *obj = (s16)((u32)param_2[0x18] << 8);
  v = *(u16 *)((char *)obj + 0xb0);
  v |= 0x4000;
  *(u16 *)((char *)obj + 0xb0) = (u16)v;
}

#pragma peephole off
#pragma scheduling off
void duster_render(int obj, int p2, int p3, int p4, int p5, s8 visible) {
  int state = *(int *)(obj + 0xb8);
  if (visible != 0) {
    if (*(u8 *)(state + 0x1b) != 0) {
      if (*(u8 *)(state + 0x1c) == 0) {
        ((void(*)(int,int,int,int,int,f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E38B0);
      }
    }
  }
}
#pragma scheduling reset
#pragma peephole reset

extern int objBboxFn_800640cc(f32 *from, f32 *to, f32 radius, int mode, void *hit,
                              void *obj, int flags, int mask, int arg9, int arg10);
extern f32 lbl_803E38B4;

#pragma scheduling off
#pragma peephole off
void duster_hitDetect(int param_1) {
  int obj = param_1;
  int state;
  u8 hit[0x54];
  int r;
  state = *(int *)(obj + 0xb8);
  r = objBboxFn_800640cc((f32 *)(obj + 128), (f32 *)(obj + 12),
                         lbl_803E38B4, 2, hit, (void *)obj, 8, -1, 255, 0);
  if (r != 0) {
    *(u8 *)(state + 0x1a) = 1;
  }
  *(f32 *)(obj + 128) = *(f32 *)(obj + 12);
  *(f32 *)(obj + 132) = *(f32 *)(obj + 16);
  *(f32 *)(obj + 136) = *(f32 *)(obj + 20);
}
#pragma peephole reset
#pragma scheduling reset

extern void MagicPlant_update();
extern f32 lbl_803E385C;
extern void *gMapEventInterface;

#pragma scheduling off
#pragma peephole off
void MagicPlant_init(int obj, u8 *params) {
    int state;
    s32 r;
    f32 t;
    int divisor;

    state = *(int *)(obj + 0xb8);
    ObjGroup_AddObject(obj, 52);
    ObjGroup_AddObject(obj, 62);
    r = ((int (**)(int))((int **)gMapEventInterface)[0])[26](*(int *)(params + 20));
    if (r == 0) {
        t = (f32)((int (**)(int))((int **)gMapEventInterface)[0])[27](*(int *)(params + 20));
        divisor = *(u16 *)(params + 24);
        if (divisor < 100) divisor = 100;
        t = t / (f32)divisor;
        if (t > lbl_803E3858) {
            t = lbl_803E3858;
        } else if (t < lbl_803E385C) {
            t = lbl_803E385C;
        }
        *(f32 *)(state + 4) = lbl_803E3858 - t;
    } else {
        *(f32 *)(state + 4) = lbl_803E3858;
    }
    *(u8 *)(state + 15) = 0;
    *(f32 *)(state + 8) = lbl_803E385C;
    ObjAnim_SetMoveProgress((double)*(f32 *)(state + 4), (ObjAnimComponent *)obj);
    *(s16 *)obj = (s16)((u32)params[29] << 8);
    *(u16 *)(obj + 0xb0) |= 0x2000;
    *(s8 *)(obj + 0xad) = (s8)params[28];
    if ((s8)*(u8 *)(obj + 0xad) >= (s8)*(u8 *)(*(int *)(obj + 0x50) + 0x55)) {
        *(u8 *)(obj + 0xad) = 0;
    }
    if (*(int *)(obj + 0x64) != 0) {
        *(u32 *)(*(int *)(obj + 0x64) + 48) |= 0x810;
    }
    *(void **)(obj + 0xbc) = (void *)fn_8017F8C8;
}
#pragma peephole reset
#pragma scheduling reset
extern void trickyguard_update();
extern void duster_update();
extern void duster_init();
extern void curvefish_update();
extern f32 lbl_803E3928;
extern f64 lbl_803E3918;

#pragma scheduling off
#pragma peephole off
void trickywarp_update(int param_1) {
  int obj = param_1;
  TrickyWarpState *state;
  int r;
  state = *(TrickyWarpState **)(obj + 0xb8);
  r = fn_8017FFD0(obj, state);
  if (r != 0) {
    if (state->active == 0) {
      state->active = 1;
      ObjGroup_AddObject(obj, 0x4b);
    }
  } else {
    if (state->active != 0) {
      state->active = 0;
      ObjGroup_RemoveObject(obj, 0x4b);
    }
  }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
void curvefish_init(int obj, u8 *param_2) {
  int state;
  u32 v;
  state = *(int *)(obj + 0xb8);
  v = *(u16 *)(obj + 0xb0);
  v |= 0x6000;
  *(u16 *)(obj + 0xb0) = (u16)v;
  *(f32 *)(obj + 8) = *(f32 *)(*(int *)(obj + 0x50) + 4) *
                      ((f32)(u32)param_2[0x18] / lbl_803E3928);
  *(u8 *)(state + 0x108) = 1;
  *(f32 *)(state + 0x110) = (f32)(u32)param_2[0x19] / lbl_803E3928;
}
#pragma scheduling reset

typedef struct DusterHitEffectPos {
  u8 pad00[0xc];
  f32 x;
  f32 y;
  f32 z;
} DusterHitEffectPos;

#pragma scheduling off
#pragma peephole off
void fn_801814D0(int obj, int param_2, u8 *state) {
  int hitWork[4];
  DusterHitEffectPos effectPos;
  int hitType;
  int *objects;
  int i;
  f32 groupObjY;
  f32 objY;
  f32 f;

  hitType = ObjHits_GetPriorityHitWithPosition(obj,&hitWork[3],&hitWork[2],&hitWork[1],
                                               &effectPos.x,&effectPos.y,&effectPos.z);
  if (hitType != 0) {
    if (hitType == 0x10) {
      Obj_StartModelFadeIn(obj,0x12c);
    } else {
      effectPos.x += playerMapOffsetX;
      effectPos.z += playerMapOffsetZ;
      if (state[0x20] != 0) {
        if (hitType != 5) {
          objLightFn_8009a1dc(obj,lbl_803E3934,&effectPos,4,0);
          if (Sfx_IsPlayingFromObject(0,0x37e) == 0) {
            Sfx_PlayFromObject(obj,0x37e);
          }
          return;
        }
        objects = (int *)ObjGroup_GetObjects(0x10,&hitWork[0]);
        for (i = 0; i < hitWork[0]; i++) {
          if (ObjHits_IsObjectEnabled(*objects) != 0) {
            groupObjY = *(f32 *)(*objects + 0x10);
            objY = *(f32 *)(obj + 0x10);
            if (objY < groupObjY && groupObjY < objY + lbl_803DBDA8) {
              if (Vec_xzDistance((f32 *)(*objects + 0x18),(f32 *)(obj + 0x18)) < lbl_803DBDA4) {
                ObjHits_RecordObjectHit(*objects,hitWork[3],5,1,0);
              }
            }
          }
          objects++;
        }
      }
      objLightFn_8009a1dc(obj,lbl_803E3934,&effectPos,1,0);
      Obj_SetModelColorFadeRecursive(obj,0xf,0xc8,0,0,1);
      if (Sfx_IsPlayingFromObject(0,(u16)*(s16 *)(state + 0x10)) == 0) {
        Sfx_PlayFromObject(obj,(u16)*(s16 *)(state + 0x10));
      }
      *(s16 *)(state + 0xa) = 0x32;
      state[9] = 0;
      fn_801816F8(obj,param_2,state);
      *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 8);
      f = lbl_803E3938;
      *(f32 *)(obj + 0x24) = lbl_803E3938;
      *(f32 *)(obj + 0x2c) = f;
      ObjHits_ClearHitVolumes(obj);
      if (lbl_803DBDA0 != 0) {
        ObjHits_DisableObject(obj);
      }
    }
  }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void trickyguard_update(int *obj) {
    int *tricky;
    int *def = *(int **)((char *)obj + 0x4c);
    *(u8 *)((char *)obj + 0xaf) = (u8)(*(u8 *)((char *)obj + 0xaf) | 8);
    if (*(s16 *)((char *)def + 0x1a) != -1) {
        if ((u32)GameBit_Get(*(s16 *)((char *)def + 0x1a)) == 0) return;
    }
    tricky = (int *)getTrickyObject();
    if (tricky == NULL) return;
    if ((u8)((int (*)(int *))(**(int ***)((char *)tricky + 0x68))[0x11])(tricky) != 0) return;
    if ((*(u8 *)((char *)obj + 0xaf) & 0x04) != 0) {
        ((void (*)(int *, int *, int, int))(**(int ***)((char *)tricky + 0x68))[0xa])(tricky, obj, 1, 3);
    }
    *(u8 *)((char *)obj + 0xaf) = (u8)(*(u8 *)((char *)obj + 0xaf) & ~0x08);
    objRenderFn_80041018(obj);
}
#pragma peephole reset
#pragma scheduling reset

typedef struct StayPointSetup {
    u8 pad00[0x1e];
    s16 activeGameBit;
    s16 requiredGameBit;
} StayPointSetup;

#pragma scheduling off
#pragma peephole off
void StayPoint_update(int obj) {
    StayPointSetup *setup;
    void *tricky;
    int isCurrentStayPoint;

    setup = *(StayPointSetup **)(obj + 0x4c);
    tricky = getTrickyObject();
    *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 8);
    if (tricky != NULL) {
        isCurrentStayPoint = (obj - fn_80138F84((int)tricky) == 0);
        if (isCurrentStayPoint == 0 && setup->activeGameBit != -1) {
            GameBit_Set(setup->activeGameBit,0);
        }
        if (setup->requiredGameBit == -1 || GameBit_Get(setup->requiredGameBit) != 0) {
            if (isCurrentStayPoint != 0 &&
                vec3f_distanceSquared((f32 *)(obj + 0x18),(f32 *)((int)tricky + 0x18)) < lbl_803E38A8) {
                if (setup->activeGameBit != -1) {
                    GameBit_Set(setup->activeGameBit,1);
                }
                return;
            }
            if (cMenuGetSelectedItem() == -1) {
                *(u8 *)(*(int *)(*(int *)(obj + 0x50) + 0x40) + 0x11) = 0;
            } else {
                *(u8 *)(*(int *)(*(int *)(obj + 0x50) + 0x40) + 0x11) = 0x10;
            }
            *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) & ~8);
            if (((*(u32 *)(*(int *)(obj + 0x50) + 0x44) & 1) != 0) && *(void **)(obj + 0x74) != NULL) {
                objRenderFn_80041018((int *)obj);
            }
            if ((*(u8 *)(obj + 0xaf) & 4) != 0) {
                ((void (*)(void *, int, int, int))(*(int *)(*(int *)(*(int *)((int)tricky + 0x68)) + 0x28)))(
                    tricky,obj,1,3);
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

ObjectDescriptor gMagicPlantObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)MagicPlant_init,
    (ObjectDescriptorCallback)MagicPlant_update,
    0,
    (ObjectDescriptorCallback)MagicPlant_render,
    (ObjectDescriptorCallback)MagicPlant_free,
    (ObjectDescriptorCallback)MagicPlant_getObjectTypeId,
    MagicPlant_getExtraSize,
};

ObjectDescriptor gTrickyWarpObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)trickywarp_init,
    (ObjectDescriptorCallback)trickywarp_update,
    0,
    0,
    (ObjectDescriptorCallback)trickywarp_free,
    0,
    trickywarp_getExtraSize,
};

ObjectDescriptor gTrickyGuardObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)trickyguard_init,
    (ObjectDescriptorCallback)trickyguard_update,
    0,
    0,
    0,
    0,
    0,
};

ObjectDescriptor gStayPointObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)StayPoint_init,
    (ObjectDescriptorCallback)StayPoint_update,
    0,
    0,
    0,
    0,
    0,
};

ObjectDescriptor gDusterObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)duster_init,
    (ObjectDescriptorCallback)duster_update,
    (ObjectDescriptorCallback)duster_hitDetect,
    (ObjectDescriptorCallback)duster_render,
    0,
    0,
    duster_getExtraSize,
};

ObjectDescriptor gCurveFishObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)curvefish_init,
    (ObjectDescriptorCallback)curvefish_update,
    0,
    0,
    0,
    0,
    curvefish_getExtraSize,
};
