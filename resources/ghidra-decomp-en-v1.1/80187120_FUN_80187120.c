// Function: FUN_80187120
// Entry: 80187120
// Size: 1256 bytes

/* WARNING: Removing unreachable block (ram,0x801875e0) */
/* WARNING: Removing unreachable block (ram,0x80187130) */

void FUN_80187120(uint param_1)

{
  byte bVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  uint uVar6;
  undefined4 in_r10;
  int *piVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  float fVar12;
  float fVar13;
  float fVar14;
  undefined8 local_38;
  
  piVar7 = *(int **)(param_1 + 0xb8);
  iVar3 = FUN_8002bac4();
  *(undefined4 *)(param_1 + 0x80) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(param_1 + 0x84) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(param_1 + 0x88) = *(undefined4 *)(param_1 + 0x14);
  if (FLOAT_803e4738 < (float)piVar7[0x10]) {
    piVar7[0x10] = (int)((float)piVar7[0x10] - FLOAT_803e4738);
    bVar1 = *(byte *)(piVar7 + 0x1b);
    if (bVar1 < 4) {
      FUN_80186e28(param_1);
    }
    else if (bVar1 == 7) {
      *(undefined *)(piVar7 + 0x1b) = 0;
    }
    else {
      *(byte *)(piVar7 + 0x1b) = bVar1 + 1;
    }
    FUN_80186f34(param_1);
  }
  dVar8 = FUN_80010f00((double)(float)piVar7[0x10],(float *)(piVar7 + 1),(float *)0x0);
  *(float *)(param_1 + 0xc) = (float)((double)(float)piVar7[0x15] + dVar8);
  dVar8 = FUN_80010f00((double)(float)piVar7[0x10],(float *)(piVar7 + 5),(float *)0x0);
  *(float *)(param_1 + 0x10) = (float)((double)(float)piVar7[0x16] + dVar8);
  dVar8 = FUN_80010f00((double)(float)piVar7[0x10],(float *)(piVar7 + 9),(float *)0x0);
  *(float *)(param_1 + 0x14) = (float)((double)(float)piVar7[0x17] + dVar8);
  if (*(byte *)(piVar7 + 0x1c) >> 6 == 1) {
    iVar4 = FUN_8002bac4();
    dVar8 = (double)FUN_800217c8((float *)(param_1 + 0x18),(float *)(iVar4 + 0x18));
    piVar7[0x11] = (int)(float)((double)FLOAT_803e475c * dVar8 + (double)FLOAT_803e4758);
  }
  piVar7[0x10] = (int)((float)piVar7[0x11] * FLOAT_803dc074 + (float)piVar7[0x10]);
  if ((((*(char *)((int)piVar7 + 0x6a) == '\x01') || (*(char *)((int)piVar7 + 0x6a) == '\x04')) &&
      (*(byte *)(piVar7 + 0x1c) >> 6 == 1)) && (*(char *)((int)piVar7 + 0x6e) == '\0')) {
    *(undefined *)((int)piVar7 + 0x6e) = 1;
    piVar5 = FUN_8001f58c(param_1,'\x01');
    if (piVar5 == (int *)0x0) {
      piVar5 = (int *)0x0;
    }
    else {
      FUN_8001dbf0((int)piVar5,2);
      FUN_8001dbb4((int)piVar5,100,0xff,100,0);
      FUN_8001dbd8((int)piVar5,1);
      FUN_8001dcfc((double)FLOAT_803e4730,(double)FLOAT_803e4734,(int)piVar5);
      FUN_8001de04((int)piVar5,1);
    }
    *piVar7 = (int)piVar5;
    if (*(byte *)(piVar7 + 0x1c) >> 6 != 1) {
      DAT_803de758 = 1;
    }
  }
  fVar12 = *(float *)(param_1 + 0xc) - *(float *)(param_1 + 0x80);
  dVar11 = (double)fVar12;
  fVar13 = *(float *)(param_1 + 0x10) - *(float *)(param_1 + 0x84);
  fVar14 = *(float *)(param_1 + 0x14) - *(float *)(param_1 + 0x88);
  dVar8 = FUN_80293900((double)(fVar14 * fVar14 + (float)(dVar11 * dVar11) + fVar13 * fVar13));
  dVar10 = (double)fVar12;
  dVar9 = (double)FLOAT_803e4738;
  dVar8 = (double)(float)(dVar9 / (double)(float)((double)CONCAT44(0x43300000,
                                                                   (int)(dVar8 / (double)
                                                  FLOAT_803e4760) + 1U ^ 0x80000000) -
                                                 DOUBLE_803e4748));
  if (*(byte *)(piVar7 + 0x1c) >> 6 == 1) {
    FUN_8000da78(param_1,0x43b);
    dVar8 = (double)(float)((double)CONCAT44(0x43300000,piVar7[0x18] ^ 0x80000000) - DOUBLE_803e4748
                           );
    if ((double)FLOAT_803dca40 < dVar8) {
      if ((*(char *)((int)piVar7 + 0x6a) == '\x01') || (*(char *)((int)piVar7 + 0x6a) == '\x04')) {
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x19f,0,1,0xffffffff,0);
        dVar8 = (double)(**(code **)(*DAT_803dd708 + 8))(param_1,0x1a0,0,1,0xffffffff,0);
      }
      else {
        dVar8 = (double)(**(code **)(*DAT_803dd708 + 8))(param_1,0x1bd,0,1,0xffffffff,0);
      }
    }
    uVar6 = (uint)DAT_803dc070;
    iVar4 = piVar7[0x18];
    piVar7[0x18] = iVar4 - uVar6;
    if ((int)(iVar4 - uVar6) < 0) {
      FUN_8001ffac(0x698);
      FUN_8002cc9c(dVar8,dVar9,dVar10,dVar11,in_f5,in_f6,in_f7,in_f8,param_1);
    }
    else {
      uVar2 = *(undefined4 *)(iVar3 + 0x20);
      fVar12 = FLOAT_803e4740 + *(float *)(iVar3 + 0x1c);
      iVar4 = *(int *)(param_1 + 0xb8);
      *(undefined4 *)(iVar4 + 0x54) = *(undefined4 *)(iVar3 + 0x18);
      *(float *)(iVar4 + 0x58) = fVar12;
      *(undefined4 *)(iVar4 + 0x5c) = uVar2;
      if ((*piVar7 != 0) && (piVar7[0x18] < 0xb4)) {
        dVar8 = (double)FUN_802945e0();
        local_38 = (double)CONCAT44(0x43300000,piVar7[0x18] ^ 0x80000000);
        dVar8 = (double)(float)((double)(float)(local_38 - DOUBLE_803e4748) * dVar8);
        FUN_8000da78(0,0x460);
        FUN_8001dcfc(dVar8,(double)(float)((double)FLOAT_803e476c + dVar8),*piVar7);
      }
    }
  }
  else {
    (**(code **)(*DAT_803dd708 + 8))
              (param_1,0x19f,0,1,0xffffffff,0,*DAT_803dd708,in_r10,(float)(dVar10 * dVar8),
               (float)((double)fVar13 * dVar8),(float)((double)fVar14 * dVar8));
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x1a0,0,1,0xffffffff,0);
  }
  return;
}

