// Function: FUN_8017e1a0
// Entry: 8017e1a0
// Size: 1988 bytes

/* WARNING: Removing unreachable block (ram,0x8017e93c) */
/* WARNING: Removing unreachable block (ram,0x8017e944) */

void FUN_8017e1a0(void)

{
  float fVar1;
  undefined2 *puVar2;
  undefined4 uVar3;
  int iVar4;
  undefined4 *puVar5;
  int *piVar6;
  int iVar7;
  int iVar8;
  undefined4 uVar9;
  undefined8 in_f30;
  double dVar10;
  undefined8 in_f31;
  double dVar11;
  int local_78;
  undefined auStack116 [4];
  double local_70;
  longlong local_68;
  undefined4 local_60;
  uint uStack92;
  longlong local_58;
  undefined4 local_50;
  uint uStack76;
  longlong local_48;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar9 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  puVar2 = (undefined2 *)FUN_802860dc();
  iVar8 = *(int *)(puVar2 + 0x5c);
  iVar7 = *(int *)(puVar2 + 0x26);
  local_78 = 0;
  if ((*(byte *)(iVar8 + 0x5a) & 4) != 0) {
    while (iVar4 = FUN_800374ec(puVar2,&local_78,0,0), iVar4 != 0) {
      if (local_78 == 0x7000b) {
        uVar3 = FUN_8002b9ec();
        FUN_80296afc(uVar3,*(undefined2 *)(iVar8 + 0x38));
        FUN_800999b4((double)FLOAT_803e37c8,puVar2,0xff,0x28);
        FUN_8000bb18(puVar2,0x58);
        iVar4 = *(int *)(puVar2 + 0x5c);
        if ((puVar2[3] & 0x2000) == 0) {
          if (*(int *)(puVar2 + 0x2a) != 0) {
            FUN_80035f00(puVar2);
          }
          *(byte *)(iVar4 + 0x5a) = *(byte *)(iVar4 + 0x5a) | 2;
        }
        else {
          FUN_8002cbc4(puVar2);
        }
        *(byte *)(iVar8 + 0x5a) = *(byte *)(iVar8 + 0x5a) & 0xfb;
      }
    }
    if ((*(byte *)(iVar8 + 0x5a) & 4) != 0) goto switchD_8017e30c_caseD_7;
  }
  if ((*(byte *)(iVar8 + 0x5a) & 2) == 0) {
    *(float *)(iVar8 + 8) = *(float *)(iVar8 + 8) + FLOAT_803db414;
    *(float *)(iVar8 + 0xc) = *(float *)(iVar8 + 0xc) + FLOAT_803db414;
    fVar1 = *(float *)(iVar8 + 8);
    dVar11 = (double)(fVar1 / *(float *)(iVar8 + 4));
    switch(*(undefined *)(iVar8 + 0x3a)) {
    case 0:
      iVar4 = FUN_8003687c(puVar2,0,0,0);
      if ((iVar4 == 0) && ((*(short *)(iVar7 + 0x26) == -1 || (iVar7 = FUN_8001ffb4(), iVar7 == 0)))
         ) {
        if (dVar11 <= (double)*(float *)(iVar8 + 0x10)) {
          iVar7 = *(int *)(puVar2 + 0x5c);
          *(float *)(puVar2 + 4) =
               *(float *)(*(int *)(puVar2 + 0x28) + 4) *
               (*(float *)(iVar7 + 8) / *(float *)(iVar7 + 4)) *
               (FLOAT_803e37c8 / *(float *)(iVar7 + 0x10));
        }
        else {
          *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(*(int *)(puVar2 + 0x28) + 4);
          *(undefined *)(iVar8 + 0x3a) = 1;
        }
      }
      else {
        iVar8 = *(int *)(puVar2 + 0x5c);
        iVar7 = 0;
        do {
          (**(code **)(*DAT_803dca88 + 8))(puVar2,0x55a,0,2,0xffffffff,0);
          iVar7 = iVar7 + 1;
        } while (iVar7 < 8);
        if (*(int *)(puVar2 + 0x2a) != 0) {
          FUN_80035f00(puVar2);
        }
        *(byte *)(iVar8 + 0x5a) = *(byte *)(iVar8 + 0x5a) | 2;
        *(float *)(iVar8 + 8) = FLOAT_803db414;
        *(undefined *)(iVar8 + 0x3a) = 5;
      }
      break;
    case 1:
      iVar4 = FUN_8003687c(puVar2,0,0,0);
      if ((iVar4 == 0) && ((*(short *)(iVar7 + 0x26) == -1 || (iVar7 = FUN_8001ffb4(), iVar7 == 0)))
         ) {
        if (dVar11 <= (double)*(float *)(iVar8 + 0x14)) {
          iVar7 = (**(code **)(*DAT_803dca58 + 0x24))(auStack116);
          if (iVar7 == 0) {
            FUN_8002fa48((double)FLOAT_803e3808,(double)FLOAT_803db414,puVar2,0);
          }
          else {
            FUN_8002fa48((double)FLOAT_803e3804,(double)FLOAT_803db414,puVar2,0);
          }
        }
        else {
          iVar7 = 0;
          do {
            (**(code **)(*DAT_803dca88 + 8))(puVar2,0x55a,0,2,0xffffffff,0);
            iVar7 = iVar7 + 1;
          } while (iVar7 < 8);
          *(undefined *)(iVar8 + 0x3a) = 2;
        }
      }
      else {
        iVar8 = *(int *)(puVar2 + 0x5c);
        iVar7 = 0;
        do {
          (**(code **)(*DAT_803dca88 + 8))(puVar2,0x55a,0,2,0xffffffff,0);
          iVar7 = iVar7 + 1;
        } while (iVar7 < 8);
        if (*(int *)(puVar2 + 0x2a) != 0) {
          FUN_80035f00(puVar2);
        }
        *(byte *)(iVar8 + 0x5a) = *(byte *)(iVar8 + 0x5a) | 2;
        *(float *)(iVar8 + 8) = FLOAT_803db414;
        *(undefined *)(iVar8 + 0x3a) = 5;
      }
      break;
    case 2:
      if (dVar11 <= (double)*(float *)(iVar8 + 0x18)) {
        iVar4 = *(int *)(puVar2 + 0x5c);
        fVar1 = *(float *)(iVar4 + 8);
        dVar11 = (double)(-(*(float *)(iVar4 + 4) * *(float *)(iVar4 + 0x14) - fVar1) /
                         (*(float *)(iVar4 + 4) *
                         (*(float *)(iVar4 + 0x18) - *(float *)(iVar4 + 0x14))));
        fVar1 = fVar1 * fVar1 * fVar1 * fVar1;
        iVar8 = (int)((fVar1 * fVar1) / *(float *)(iVar4 + 0x54));
        local_70 = (double)(longlong)iVar8;
        piVar6 = (int *)FUN_800394ac(puVar2,0,0);
        *piVar6 = 0x100 - iVar8;
        *(float *)(iVar4 + 0x24) = (float)((double)FLOAT_803e37d0 * dVar11 + (double)FLOAT_803e37cc)
        ;
        *(float *)(puVar2 + 4) = *(float *)(*(int *)(puVar2 + 0x28) + 4) * *(float *)(iVar4 + 0x24);
        FUN_8002b884(puVar2,1);
      }
      else {
        iVar4 = *(int *)(puVar2 + 0x5c);
        puVar5 = (undefined4 *)FUN_800394ac(puVar2,0,0);
        *puVar5 = 0;
        *(float *)(iVar4 + 0x24) = FLOAT_803e37c8;
        *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(*(int *)(puVar2 + 0x28) + 4);
        FUN_8002b884(puVar2,1);
        *(undefined *)(iVar8 + 0x3a) = 3;
      }
      iVar8 = FUN_8003687c(puVar2,0,0,0);
      if ((iVar8 != 0) || ((*(short *)(iVar7 + 0x26) != -1 && (iVar7 = FUN_8001ffb4(), iVar7 != 0)))
         ) {
        FUN_8017d854(puVar2,1);
      }
      break;
    case 3:
      *(float *)(iVar8 + 8) = fVar1 - FLOAT_803db414;
      if (dVar11 <= (double)*(float *)(iVar8 + 0x1c)) {
        iVar8 = FUN_8003687c(puVar2,0,0,0);
        if ((iVar8 != 0) ||
           ((*(short *)(iVar7 + 0x26) != -1 && (iVar7 = FUN_8001ffb4(), iVar7 != 0)))) {
          FUN_8017d854(puVar2,2);
        }
      }
      else {
        FUN_8017d854(puVar2,0);
      }
      break;
    case 4:
      if (dVar11 <= (double)*(float *)(iVar8 + 0x20)) {
        iVar7 = 0;
        iVar4 = 0;
        dVar10 = (double)FLOAT_803e37d4;
        do {
          if (iVar7 != 0) break;
          fVar1 = *(float *)(iVar8 + 0xc);
          if ((double)*(float *)(iVar8 + 0x28) <= dVar10) {
            iVar7 = FUN_8017dcd4((double)(fVar1 * fVar1 * (*(float *)(iVar8 + 0x40) +
                                                          *(float *)(iVar8 + 0x3c)) +
                                         *(float *)(iVar8 + 0x44) * fVar1 + *(float *)(iVar8 + 0x2c)
                                         ),puVar2,iVar8);
          }
          else {
            iVar7 = FUN_8017df34(puVar2,iVar8);
          }
          iVar4 = iVar4 + 1;
        } while ((iVar4 == 100) || (iVar4 != 0x66));
        dVar10 = DOUBLE_803e3820;
        if (FLOAT_803e37d4 != *(float *)(iVar8 + 0x30)) {
          fVar1 = *(float *)(iVar8 + 0xc) / *(float *)(iVar8 + 0x50);
          local_70 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar8 + 0x48) ^ 0x80000000);
          iVar7 = (int)((float)(local_70 - DOUBLE_803e3820) * fVar1);
          local_68 = (longlong)iVar7;
          *puVar2 = (short)iVar7;
          uStack92 = (int)*(short *)(iVar8 + 0x4a) ^ 0x80000000;
          local_60 = 0x43300000;
          iVar7 = (int)((float)((double)CONCAT44(0x43300000,uStack92) - dVar10) * fVar1);
          local_58 = (longlong)iVar7;
          puVar2[1] = (short)iVar7;
          uStack76 = (int)*(short *)(iVar8 + 0x4c) ^ 0x80000000;
          local_50 = 0x43300000;
          iVar7 = (int)((float)((double)CONCAT44(0x43300000,uStack76) - dVar10) * fVar1);
          local_48 = (longlong)iVar7;
          puVar2[2] = (short)iVar7;
        }
        piVar6 = (int *)FUN_800394ac(puVar2,0,0);
        local_48 = (longlong)(int)((double)FLOAT_803e380c * dVar11);
        *piVar6 = (int)((double)FLOAT_803e380c * dVar11);
        FUN_8017daf0(puVar2);
      }
      else {
        *(undefined *)(iVar8 + 0x3a) = 6;
        *(float *)(iVar8 + 8) = FLOAT_803db414;
      }
      break;
    case 5:
      if (FLOAT_803e3810 < fVar1) {
        iVar7 = *(int *)(puVar2 + 0x5c);
        if ((puVar2[3] & 0x2000) == 0) {
          if (*(int *)(puVar2 + 0x2a) != 0) {
            FUN_80035f00(puVar2);
          }
          *(byte *)(iVar7 + 0x5a) = *(byte *)(iVar7 + 0x5a) | 2;
        }
        else {
          FUN_8002cbc4(puVar2);
        }
      }
      break;
    case 6:
      if (fVar1 <= FLOAT_803e3814) {
        iVar7 = (int)((FLOAT_803e3818 * fVar1) / FLOAT_803e3814);
        local_48 = (longlong)iVar7;
        *(char *)(puVar2 + 0x1b) = -1 - (char)iVar7;
        FUN_8017daf0(puVar2);
      }
      else {
        iVar7 = *(int *)(puVar2 + 0x5c);
        if ((puVar2[3] & 0x2000) == 0) {
          if (*(int *)(puVar2 + 0x2a) != 0) {
            FUN_80035f00(puVar2);
          }
          *(byte *)(iVar7 + 0x5a) = *(byte *)(iVar7 + 0x5a) | 2;
        }
        else {
          FUN_8002cbc4(puVar2);
        }
      }
    }
  }
switchD_8017e30c_caseD_7:
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  __psq_l0(auStack24,uVar9);
  __psq_l1(auStack24,uVar9);
  FUN_80286128();
  return;
}

