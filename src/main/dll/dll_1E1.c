#include "ghidra_import.h"
#include "main/dll/dll_1E1.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined4 FUN_8001771c();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017a30();
extern byte FUN_80017a34();
extern undefined4 FUN_80017a3c();
extern undefined4 FUN_80017a68();
extern int FUN_80017a98();
extern int FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_ClearHitVolumes();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_RecordObjectHit();
extern int ObjHits_GetPriorityHitWithPosition();
extern undefined4 FUN_80081120();
extern undefined4 FUN_801d1e24();
extern undefined4 FUN_80286840();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern double FUN_80294c4c();
extern byte FUN_80294ca8();
extern int FUN_80294cb0();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
extern f64 DOUBLE_803e5fa0;
extern f64 DOUBLE_803e5fe0;
extern f32 lbl_803DC074;
extern f32 lbl_803DDA58;
extern f32 lbl_803DDA5C;
extern f32 lbl_803E5F90;
extern f32 lbl_803E5F94;
extern f32 lbl_803E5FB0;
extern f32 lbl_803E5FB4;
extern f32 lbl_803E5FB8;
extern f32 lbl_803E5FBC;
extern f32 lbl_803E5FC0;
extern f32 lbl_803E5FC4;
extern f32 lbl_803E5FC8;
extern f32 lbl_803E5FCC;
extern f32 lbl_803E5FD0;
extern f32 lbl_803E5FD4;
extern f32 lbl_803E5FD8;

/*
 * --INFO--
 *
 * Function: dll1E1_updateTrickyState
 * EN v1.0 Address: 0x801D1E24
 * EN v1.0 Size: 2644b
 * EN v1.1 Address: 0x801D2414
 * EN v1.1 Size: 2452b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll1E1_updateTrickyState
          (undefined8 param_1,double param_2,double param_3,undefined8 param_4,
           undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  float fVar1;
  float fVar2;
  ushort *puVar3;
  int iVar4;
  byte bVar7;
  int iVar5;
  uint uVar6;
  uint *puVar8;
  float *pfVar9;
  float *pfVar10;
  float *pfVar11;
  undefined4 in_r10;
  char cVar12;
  int iVar13;
  float *pfVar14;
  double dVar15;
  uint uStack_58;
  int iStack_54;
  undefined4 uStack_50;
  undefined auStack_4c [12];
  float local_40;
  float local_3c;
  float local_38 [2];
  undefined8 local_30;
  undefined4 local_28;
  uint uStack_24;
  undefined8 local_20;
  
  puVar3 = (ushort *)FUN_80286840();
  pfVar14 = *(float **)(puVar3 + 0x5c);
  iVar4 = FUN_80017a98();
  iVar13 = *(int *)(puVar3 + 0x26);
  ObjHits_ClearHitVolumes((int)puVar3);
  *(byte *)((int)puVar3 + 0xaf) = *(byte *)((int)puVar3 + 0xaf) | 8;
  *(byte *)((int)pfVar14 + 0x37) = *(byte *)((int)pfVar14 + 0x37) | 4;
  bVar7 = FUN_80017a34((int)puVar3);
  if (bVar7 == 0) {
    if ((*(ushort *)(iVar4 + 0xb0) & 0x1000) == 0) {
      switch(*(undefined *)((int)pfVar14 + 0x36)) {
      default:
        *(byte *)((int)puVar3 + 0xaf) = *(byte *)((int)puVar3 + 0xaf) & 0xf7;
        fVar1 = *(float *)(iVar4 + 0xc) - *(float *)(puVar3 + 6);
        param_3 = (double)(*(float *)(iVar4 + 0x10) - *(float *)(puVar3 + 8));
        fVar2 = *(float *)(iVar4 + 0x14) - *(float *)(puVar3 + 10);
        dVar15 = FUN_80293900((double)(fVar2 * fVar2 + fVar1 * fVar1 + (float)(param_3 * param_3)));
        local_30 = (double)(longlong)(int)dVar15;
        param_2 = (double)lbl_803E5FD0;
        uStack_24 = (uint)*(byte *)(iVar13 + 0x1e);
        local_28 = 0x43300000;
        uVar6 = (uint)(param_2 *
                      (double)(float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e5fe0));
        local_20 = (double)(longlong)(int)uVar6;
        if ((((int)dVar15 & 0xffffU) < (uVar6 & 0xffff)) &&
           (dVar15 = FUN_80294c4c(iVar4), (double)lbl_803E5FD4 <= dVar15)) {
          *(byte *)((int)pfVar14 + 0x37) = *(byte *)((int)pfVar14 + 0x37) & 0xfe;
          *(undefined *)((int)pfVar14 + 0x36) = 3;
          *pfVar14 = lbl_803E5F94;
          FUN_80006824((uint)puVar3,0x48e);
        }
        break;
      case 1:
        *(byte *)((int)pfVar14 + 0x37) = *(byte *)((int)pfVar14 + 0x37) & 0xfb;
        if (pfVar14[1] < *(float *)(puVar3 + 4)) {
          pfVar14[4] = pfVar14[4] / lbl_803E5FC0;
        }
        if (pfVar14[4] < lbl_803E5F90) {
          pfVar14[4] = lbl_803E5F94;
        }
        *pfVar14 = *pfVar14 + lbl_803DC074;
        param_2 = (double)pfVar14[4];
        *(float *)(puVar3 + 4) =
             (float)(param_2 * (double)lbl_803DC074 + (double)*(float *)(puVar3 + 4));
        if (pfVar14[2] < *pfVar14) {
          *(undefined *)((int)pfVar14 + 0x36) = 0;
        }
        break;
      case 2:
        *(byte *)((int)pfVar14 + 0x37) = *(byte *)((int)pfVar14 + 0x37) & 0xfb;
        if ((*(byte *)((int)pfVar14 + 0x37) & 2) != 0) {
          iVar4 = (uint)*(byte *)(puVar3 + 0x1b) + (uint)DAT_803dc070 * -4;
          if (iVar4 < 0) {
            iVar4 = 0;
          }
          *(char *)(puVar3 + 0x1b) = (char)iVar4;
          *pfVar14 = *pfVar14 + lbl_803DC074;
          param_2 = (double)*pfVar14;
          local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(pfVar14 + 0xd) ^ 0x80000000);
          if ((double)(float)(local_30 - DOUBLE_803e5fa0) < param_2) {
            FUN_801d1e24(puVar3,pfVar14,1);
            *(undefined *)((int)pfVar14 + 0x36) = 1;
          }
        }
        break;
      case 3:
        *(byte *)((int)puVar3 + 0xaf) = *(byte *)((int)puVar3 + 0xaf) & 0xf7;
        FUN_800068c4((uint)puVar3,0x9c);
        if ((*(byte *)((int)pfVar14 + 0x37) & 2) != 0) {
          *(undefined *)((int)pfVar14 + 0x36) = 4;
        }
        break;
      case 4:
        *(byte *)((int)puVar3 + 0xaf) = *(byte *)((int)puVar3 + 0xaf) & 0xf7;
        param_2 = (double)lbl_803E5FB8;
        pfVar14[0xb] = (float)(param_2 * (double)lbl_803DC074 + (double)pfVar14[0xb]);
        FUN_800068c4((uint)puVar3,0x9a);
        if (((((*(byte *)((int)pfVar14 + 0x37) & 1) == 0) &&
             (dVar15 = (double)FUN_8001771c((float *)(puVar3 + 0xc),(float *)(iVar4 + 0x18)),
             dVar15 <= (double)pfVar14[0xb])) && (iVar5 = FUN_80294cb0(iVar4), iVar5 == 0)) &&
           ((bVar7 = FUN_80294ca8(iVar4), bVar7 == 0 && ((*(ushort *)(iVar4 + 0xb0) & 0x1000) == 0))
           )) {
          ObjHits_RecordObjectHit(iVar4,(int)puVar3,'\x16',1,0);
          *(byte *)((int)pfVar14 + 0x37) = *(byte *)((int)pfVar14 + 0x37) | 1;
        }
        if (lbl_803E5FB4 < pfVar14[0xb]) {
          pfVar14[0xb] = lbl_803E5FB4;
        }
        *pfVar14 = *pfVar14 + lbl_803DC074;
        if (lbl_803E5FBC < *pfVar14) {
          *pfVar14 = lbl_803E5F94;
          *(undefined *)((int)pfVar14 + 0x36) = 5;
        }
        local_40 = pfVar14[8];
        local_3c = pfVar14[9];
        local_38[0] = pfVar14[10];
        for (cVar12 = '\x01'; cVar12 != '\0'; cVar12 = cVar12 + -1) {
          (**(code **)(*DAT_803dd708 + 8))(puVar3,0x3eb,auStack_4c,0x200001,0xffffffff,0);
        }
        break;
      case 5:
        *(byte *)((int)puVar3 + 0xaf) = *(byte *)((int)puVar3 + 0xaf) & 0xf7;
        *pfVar14 = *pfVar14 + lbl_803DC074;
        param_2 = (double)*pfVar14;
        local_30 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar13 + 0x18));
        if (((double)(float)(local_30 - DOUBLE_803e5fe0) < param_2) &&
           ((*(byte *)((int)pfVar14 + 0x37) & 2) != 0)) {
          *(undefined *)((int)pfVar14 + 0x36) = 0;
          pfVar14[0xb] = lbl_803E5F94;
          *(byte *)((int)pfVar14 + 0x37) = *(byte *)((int)pfVar14 + 0x37) & 0xfe;
        }
        break;
      case 6:
        FUN_800068c4((uint)puVar3,0x9a);
        *(byte *)((int)pfVar14 + 0x37) = *(byte *)((int)pfVar14 + 0x37) & 0xfb;
        param_2 = (double)lbl_803E5FB0;
        pfVar14[0xb] = (float)(param_2 * (double)lbl_803DC074 + (double)pfVar14[0xb]);
        if (lbl_803E5FB4 < pfVar14[0xb]) {
          pfVar14[0xb] = lbl_803E5FB4;
        }
        if (((((*(byte *)((int)pfVar14 + 0x37) & 1) == 0) &&
             (dVar15 = (double)FUN_8001771c((float *)(puVar3 + 0xc),(float *)(iVar4 + 0x18)),
             dVar15 <= (double)pfVar14[0xb])) && (iVar5 = FUN_80294cb0(iVar4), iVar5 == 0)) &&
           ((bVar7 = FUN_80294ca8(iVar4), bVar7 == 0 && ((*(ushort *)(iVar4 + 0xb0) & 0x1000) == 0))
           )) {
          ObjHits_RecordObjectHit(iVar4,(int)puVar3,'\x16',1,0);
          *(byte *)((int)pfVar14 + 0x37) = *(byte *)((int)pfVar14 + 0x37) | 1;
        }
        if ((*(byte *)((int)pfVar14 + 0x37) & 2) != 0) {
          *pfVar14 = lbl_803E5F94;
          *(undefined *)((int)pfVar14 + 0x36) = 2;
        }
        local_40 = pfVar14[8];
        local_3c = pfVar14[9];
        local_38[0] = pfVar14[10];
        for (cVar12 = '\x01'; cVar12 != '\0'; cVar12 = cVar12 + -1) {
          (**(code **)(*DAT_803dd708 + 8))(puVar3,0x3eb,auStack_4c,0x200001,0xffffffff,0);
        }
        break;
      case 9:
        if (*pfVar14 <= lbl_803E5F94) {
          uVar6 = randomGetRange(0xf0,300);
          local_30 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
          *pfVar14 = (float)(local_30 - DOUBLE_803e5fa0);
        }
        if ((*(byte *)((int)pfVar14 + 0x37) & 2) != 0) {
          *pfVar14 = lbl_803E5F94;
        }
        FUN_800068c4((uint)puVar3,0x9b);
        fVar1 = *pfVar14 - lbl_803DC074;
        *pfVar14 = fVar1;
        param_2 = (double)lbl_803E5F94;
        if (param_2 < (double)fVar1) {
          fVar1 = pfVar14[0xc] - lbl_803DC074;
          pfVar14[0xc] = fVar1;
          if ((double)fVar1 <= param_2) {
            local_40 = lbl_803E5FC4;
            local_3c = lbl_803E5FC8;
            (**(code **)(*DAT_803dd708 + 8))(puVar3,0x51d,auStack_4c,2,0xffffffff,0);
            pfVar14[0xc] = lbl_803E5FCC;
          }
          *(byte *)((int)puVar3 + 0xaf) = *(byte *)((int)puVar3 + 0xaf) & 0xf7;
        }
        else {
          (**(code **)(*DAT_803dd6f8 + 0x14))(puVar3);
          *(undefined *)((int)pfVar14 + 0x36) = 0;
          FUN_80017a68((int)puVar3);
        }
        break;
      case 10:
        ObjHits_DisableObject((int)puVar3);
        *pfVar14 = *pfVar14 + lbl_803DC074;
        param_2 = (double)*pfVar14;
        local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(pfVar14 + 0xd) ^ 0x80000000);
        if ((double)(float)(local_30 - DOUBLE_803e5fa0) < param_2) {
          FUN_801d1e24(puVar3,pfVar14,1);
          *(undefined *)((int)pfVar14 + 0x36) = 1;
          FUN_80017a68((int)puVar3);
        }
      }
      puVar8 = &uStack_58;
      pfVar9 = &local_40;
      pfVar10 = &local_3c;
      pfVar11 = local_38;
      iVar4 = ObjHits_GetPriorityHitWithPosition((int)puVar3,&uStack_50,&iStack_54,puVar8,pfVar9,pfVar10,pfVar11);
      local_40 = local_40 + lbl_803DDA58;
      local_38[0] = local_38[0] + lbl_803DDA5C;
      if ((iVar4 != 0) && ((*(byte *)((int)pfVar14 + 0x37) & 4) != 0)) {
        if (iVar4 == 0x10) {
          FUN_80017a3c(puVar3,300);
        }
        else {
          if (*(char *)((int)pfVar14 + 0x36) != '\t') {
            FUN_80006824((uint)puVar3,0x9d);
          }
          *(byte *)((int)pfVar14 + 0x37) = *(byte *)((int)pfVar14 + 0x37) & 0xfe;
          if ((int)*(short *)(iVar13 + 0x1c) != 0xffffffff) {
            GameBit_Set((int)*(short *)(iVar13 + 0x1c),1);
          }
          *(undefined *)((int)pfVar14 + 0x36) = 9;
          *pfVar14 = lbl_803E5F94;
          uVar6 = randomGetRange(0,0x28);
          local_20 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
          *(float *)(puVar3 + 0x4c) = (float)(local_20 - DOUBLE_803e5fa0) / lbl_803E5FD8;
        }
        puVar8 = (uint *)0x0;
        FUN_80081120(puVar3,auStack_4c,1,(int *)0x0);
      }
      iVar4 = (int)*(short *)((uint)*(byte *)((int)pfVar14 + 0x36) * 2 + -0x7fcd8748);
      if ((short)puVar3[0x50] != iVar4) {
        FUN_800305f8((double)lbl_803E5F94,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     puVar3,iVar4,0,puVar8,pfVar9,pfVar10,pfVar11,in_r10);
      }
      iVar4 = FUN_8002fc3c((double)*(float *)((uint)*(byte *)((int)pfVar14 + 0x36) * 4 + -0x7fcd8730
                                             ),(double)lbl_803DC074);
      if (iVar4 == 0) {
        *(byte *)((int)pfVar14 + 0x37) = *(byte *)((int)pfVar14 + 0x37) & 0xfd;
      }
      else {
        *(byte *)((int)pfVar14 + 0x37) = *(byte *)((int)pfVar14 + 0x37) | 2;
      }
    }
  }
  else {
    iVar4 = ObjHits_GetPriorityHitWithPosition((int)puVar3,&uStack_50,&iStack_54,&uStack_58,&local_40,&local_3c,local_38);
    if ((iVar4 != 0) && (iVar4 != 0x10)) {
      local_40 = local_40 + lbl_803DDA58;
      local_38[0] = local_38[0] + lbl_803DDA5C;
      FUN_80081120(puVar3,auStack_4c,1,(int *)0x0);
      FUN_80006824((uint)puVar3,0x47b);
      FUN_80017a30((int)puVar3);
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: enemymushroom_release
 * EN v1.0 Address: 0x801D2864
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void enemymushroom_release(void)
{
}

/*
 * --INFO--
 *
 * Function: enemymushroom_initialise
 * EN v1.0 Address: 0x801D2868
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void enemymushroom_initialise(void)
{
}

/*
 * --INFO--
 *
 * Function: bombplant_getExtraSize
 * EN v1.0 Address: 0x801D2B34
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int bombplant_getExtraSize(void)
{
  return 0x18;
}

/*
 * --INFO--
 *
 * Function: bombplant_func08
 * EN v1.0 Address: 0x801D2B3C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int bombplant_func08(void)
{
  return 0;
}

/*
 * --INFO--
 *
 * Function: bombplant_free
 * EN v1.0 Address: 0x801D2B44
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void bombplant_free(void)
{
}

/*
 * --INFO--
 *
 * Function: bombplant_hitDetect
 * EN v1.0 Address: 0x801D2B6C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void bombplant_hitDetect(void)
{
}

/* render-with-fn(lbl) (no visibility check). */
extern f32 lbl_803E5370;
extern void objRenderFn_8003b8f4(f32);
#pragma scheduling off
#pragma peephole off
void bombplant_render(void) { objRenderFn_8003b8f4(lbl_803E5370); }
#pragma peephole reset
#pragma scheduling reset
