#include "ghidra_import.h"
#include "main/dll/CAM/dll_5F.h"

extern undefined4 FUN_800033a8();
extern void Obj_TransformWorldPointToLocal(f32 x,f32 y,f32 z,float *outX,float *outY,float *outZ,int obj);
extern double mathFn_80010c64();
extern double mathFn_80010ee0();
extern undefined4 getButtonsJustPressed();
extern int FUN_80017730();
extern undefined4 FUN_80017830();
extern undefined4 fn_8010A104();
extern undefined4 pathcam_buildWindowSamples();
extern undefined8 pathcam_findTaggedNodeWindow();
extern double fn_8010AC48();
extern undefined4 fn_8010AEA8();
extern undefined4 FUN_8010b218();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_80286888();
extern undefined4 sqrtf();

extern u8 framesThisStep;
extern int *lbl_803DCA50;
extern undefined4* lbl_803DCA9C;
extern undefined4* lbl_803DD560;
extern f64 lbl_803E18A0;
extern f32 lbl_803E1888;
extern f32 lbl_803E188C;
extern f32 lbl_803E18BC;

/*
 * --INFO--
 *
 * Function: CameraModeTestStrength_update
 * EN v1.0 Address: 0x8010B424
 * EN v1.0 Size: 2392b
 * EN v1.1 Address: 0x8010B6C0
 * EN v1.1 Size: 1652b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void CameraModeTestStrength_update(short *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  float fVar1;
  byte bVar2;
  short *psVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  int iVar6;
  uint uVar7;
  undefined4 in_r6;
  float *pfVar8;
  undefined4 in_r7;
  float *pfVar9;
  undefined4 in_r8;
  float *pfVar10;
  undefined4 in_r9;
  float *pfVar11;
  undefined4 in_r10;
  float *pfVar12;
  int iVar13;
  double dVar14;
  undefined8 extraout_f1;
  undefined8 uVar15;
  double dVar16;
  undefined8 extraout_f1_00;
  undefined8 extraout_f1_01;
  undefined8 extraout_f1_02;
  undefined8 extraout_f1_03;
  double dVar17;
  double dVar18;
  double in_f28;
  double in_f29;
  double in_f30;
  double in_f31;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  float afStack_108 [4];
  float afStack_f8 [4];
  float afStack_e8 [4];
  float afStack_d8 [4];
  float afStack_c8 [4];
  float afStack_b8 [4];
  float afStack_a8 [4];
  int local_98 [2];
  int local_90;
  int local_8c;
  int local_88 [2];
  int local_80;
  int local_7c;
  undefined8 local_78;
  undefined4 local_70;
  uint uStack_6c;
  longlong local_68;
  float local_38;
  float fStack_34;
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
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  psVar3 = param_1;
  if (*(char *)((int)lbl_803DD560 + 0x65) == '\0') {
    iVar13 = *(int *)(psVar3 + 0x52);
    getButtonsJustPressed(0);
    uVar4 = (**(code **)(*lbl_803DCA9C + 0x1c))(lbl_803DD560[3]);
    uVar5 = (**(code **)(*lbl_803DCA9C + 0x1c))(lbl_803DD560[2]);
    uVar15 = pathcam_findTaggedNodeWindow(extraout_f1,param_2,param_3,param_4,param_5,param_6,
                                          param_7,param_8,uVar5,local_98,lbl_803DD560[1],in_r6,
                                          in_r7,in_r8,in_r9,in_r10);
    pathcam_findTaggedNodeWindow(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 uVar4,local_88,lbl_803DD560[1],in_r6,in_r7,in_r8,in_r9,in_r10);
    pfVar8 = afStack_c8;
    pfVar9 = afStack_d8;
    pfVar10 = afStack_e8;
    pfVar11 = afStack_f8;
    pfVar12 = afStack_108;
    pathcam_buildWindowSamples(local_98,afStack_a8,afStack_b8,pfVar8,pfVar9,pfVar10,pfVar11,
                               pfVar12);
    dVar17 = (double)*(float *)(iVar13 + 0x1c);
    dVar18 = (double)*(float *)(iVar13 + 0x20);
    dVar16 = fn_8010AC48((double)*(float *)(iVar13 + 0x18),dVar17,dVar18,local_88);
    dVar14 = (double)lbl_803E1888;
    if (dVar14 <= dVar16) {
      dVar14 = dVar16;
      if ((double)lbl_803E188C < dVar16) {
        if ((local_80 < 0) || (local_7c < 0)) {
          dVar14 = (double)lbl_803E188C;
        }
        else {
          lbl_803DD560[3] = local_80;
          uVar4 = (**(code **)(*lbl_803DCA9C + 0x1c))(lbl_803DD560[3]);
          pathcam_findTaggedNodeWindow(extraout_f1_02,dVar17,dVar18,param_4,param_5,param_6,param_7,
                                       param_8,uVar4,local_88,lbl_803DD560[1],pfVar8,pfVar9,
                                       pfVar10,pfVar11,pfVar12);
          if ((local_90 < 0) || (local_8c < 0)) {
            dVar14 = (double)lbl_803E188C;
          }
          else {
            lbl_803DD560[2] = local_90;
            uVar4 = (**(code **)(*lbl_803DCA9C + 0x1c))(lbl_803DD560[2]);
            pathcam_findTaggedNodeWindow(extraout_f1_03,dVar17,dVar18,param_4,param_5,param_6,
                                         param_7,param_8,uVar4,local_98,lbl_803DD560[1],pfVar8,
                                         pfVar9,pfVar10,pfVar11,pfVar12);
            pathcam_buildWindowSamples(local_98,afStack_a8,afStack_b8,afStack_c8,afStack_d8,
                                       afStack_e8,afStack_f8,afStack_108);
            dVar14 = fn_8010AC48((double)*(float *)(iVar13 + 0x18),
                                  (double)*(float *)(iVar13 + 0x1c),
                                  (double)*(float *)(iVar13 + 0x20),local_88);
            lbl_803DD560[0x16] = (int)((float)lbl_803DD560[0x16] - lbl_803E188C);
          }
        }
      }
    }
    else if (-1 < local_88[0]) {
      lbl_803DD560[3] = local_88[0];
      uVar4 = (**(code **)(*lbl_803DCA9C + 0x1c))(lbl_803DD560[3]);
      pathcam_findTaggedNodeWindow(extraout_f1_00,dVar17,dVar18,param_4,param_5,param_6,param_7,
                                   param_8,uVar4,local_88,lbl_803DD560[1],pfVar8,pfVar9,pfVar10,
                                   pfVar11,pfVar12);
      if (local_98[0] < 0) {
        dVar14 = (double)lbl_803E1888;
      }
      else {
        lbl_803DD560[2] = local_98[0];
        uVar4 = (**(code **)(*lbl_803DCA9C + 0x1c))(lbl_803DD560[2]);
        pathcam_findTaggedNodeWindow(extraout_f1_01,dVar17,dVar18,param_4,param_5,param_6,param_7,
                                     param_8,uVar4,local_98,lbl_803DD560[1],pfVar8,pfVar9,
                                     pfVar10,pfVar11,pfVar12);
        pathcam_buildWindowSamples(local_98,afStack_a8,afStack_b8,afStack_c8,afStack_d8,afStack_e8,
                                   afStack_f8,afStack_108);
        dVar14 = fn_8010AC48((double)*(float *)(iVar13 + 0x18),(double)*(float *)(iVar13 + 0x1c),
                              (double)*(float *)(iVar13 + 0x20),local_88);
        lbl_803DD560[0x16] = (int)((float)lbl_803DD560[0x16] + lbl_803E188C);
      }
    }
    fVar1 = (float)((double)lbl_803E18BC *
                    (double)(float)(dVar14 - (double)(float)lbl_803DD560[0x16]) +
                   (double)(float)lbl_803DD560[0x16]);
    dVar16 = (double)fVar1;
    lbl_803DD560[0x16] = (int)fVar1;
    dVar14 = mathFn_80010ee0(dVar16,afStack_a8,(float *)0x0);
    *(float *)(psVar3 + 0xc) = (float)dVar14;
    dVar14 = mathFn_80010ee0(dVar16,afStack_b8,(float *)0x0);
    *(float *)(psVar3 + 0xe) = (float)dVar14;
    dVar14 = mathFn_80010ee0(dVar16,afStack_c8,(float *)0x0);
    *(float *)(psVar3 + 0x10) = (float)dVar14;
    iVar6 = (**(code **)(*lbl_803DCA9C + 0x1c))(lbl_803DD560[2]);
    bVar2 = *(byte *)(iVar6 + 0x3b);
    if ((bVar2 & 1) == 0) {
      dVar14 = mathFn_80010c64(dVar16,afStack_d8,(float *)0x0);
      local_78 = (double)(longlong)(int)dVar14;
      *psVar3 = (short)(int)dVar14 + -0x8000;
    }
    if ((bVar2 & 2) == 0) {
      dVar14 = mathFn_80010c64(dVar16,afStack_e8,(float *)0x0);
      local_78 = (double)(longlong)(int)dVar14;
      psVar3[1] = (short)(int)dVar14;
    }
    if ((bVar2 & 4) == 0) {
      dVar14 = mathFn_80010c64(dVar16,afStack_f8,(float *)0x0);
      local_78 = (double)(longlong)(int)dVar14;
      psVar3[2] = (short)(int)dVar14;
    }
    dVar14 = mathFn_80010ee0(dVar16,afStack_108,(float *)0x0);
    *(float *)(psVar3 + 0x5a) = (float)dVar14;
    if ((*(char *)(lbl_803DD560 + 0x19) == '\0') &&
       (uVar7 = fn_8010AEA8(psVar3,(uint)bVar2), uVar7 != 0)) {
      *(undefined *)(lbl_803DD560 + 0x19) = 1;
    }
    dVar17 = (double)(*(float *)(psVar3 + 0xc) - *(float *)(iVar13 + 0x18));
    dVar14 = (double)(*(float *)(psVar3 + 0x10) - *(float *)(iVar13 + 0x20));
    if ((bVar2 & 1) != 0) {
      iVar6 = FUN_80017730();
      *psVar3 = -0x8000 - (short)iVar6;
    }
    if ((bVar2 & 2) != 0) {
      sqrtf((double)(float)(dVar17 * dVar17 + (double)(float)(dVar14 * dVar14)));
      uVar7 = FUN_80017730();
      dVar14 = mathFn_80010c64(dVar16,afStack_e8,(float *)0x0);
      local_78 = (double)CONCAT44(0x43300000,uVar7 & 0xffff ^ 0x80000000);
      uStack_6c = (ushort)psVar3[1] ^ 0x80000000;
      local_70 = 0x43300000;
      iVar6 = (int)((float)((double)(float)(local_78 - lbl_803E18A0) - dVar14) -
                   (float)((double)CONCAT44(0x43300000,uStack_6c) - lbl_803E18A0));
      local_68 = (longlong)iVar6;
      if (0x8000 < iVar6) {
        iVar6 = iVar6 + -0xffff;
      }
      if (iVar6 < -0x8000) {
        iVar6 = iVar6 + 0xffff;
      }
      psVar3[1] = psVar3[1] + (short)((int)(iVar6 * (uint)framesThisStep) >> 3);
    }
    if ((bVar2 & 4) != 0) {
      iVar13 = (int)psVar3[2] - (uint)*(ushort *)(iVar13 + 4);
      if (0x8000 < iVar13) {
        iVar13 = iVar13 + -0xffff;
      }
      if (iVar13 < -0x8000) {
        iVar13 = iVar13 + 0xffff;
      }
      psVar3[2] = psVar3[2] + (short)((int)(iVar13 * (uint)framesThisStep) >> 3);
    }
    if (*lbl_803DD560 != 0) {
      uVar4 = *(undefined4 *)(psVar3 + 0xc);
      *(undefined4 *)(*lbl_803DD560 + 0x18) = uVar4;
      *(undefined4 *)(*lbl_803DD560 + 0xc) = uVar4;
      uVar4 = *(undefined4 *)(psVar3 + 0xe);
      *(undefined4 *)(*lbl_803DD560 + 0x1c) = uVar4;
      *(undefined4 *)(*lbl_803DD560 + 0x10) = uVar4;
      uVar4 = *(undefined4 *)(psVar3 + 0x10);
      *(undefined4 *)(*lbl_803DD560 + 0x20) = uVar4;
      *(undefined4 *)(*lbl_803DD560 + 0x14) = uVar4;
    }
    Obj_TransformWorldPointToLocal((double)*(float *)(psVar3 + 0xc),(double)*(float *)(psVar3 + 0xe),
                 (double)*(float *)(psVar3 + 0x10),(float *)(psVar3 + 6),(float *)(psVar3 + 8),
                 (float *)(psVar3 + 10),*(int *)(psVar3 + 0x18));
  }
  else {
    (**(code **)(*lbl_803DCA50 + 0x1c))(0x42,0,1,0,0,0,0xff);
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: CameraModeTestStrength_init
 * EN v1.0 Address: 0x8010BD7C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8010BD34
 * EN v1.1 Size: 1128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void CameraModeTestStrength_init(undefined4 param_1,undefined4 param_2,undefined4 *param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8)
{
}


/* Trivial 4b 0-arg blr leaves. */
void CameraModeTestStrength_release(void) {}
void CameraModeTestStrength_initialise(void) {}
void fn_8010C064(void) {}
