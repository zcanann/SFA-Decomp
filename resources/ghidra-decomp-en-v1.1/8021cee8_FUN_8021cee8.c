// Function: FUN_8021cee8
// Entry: 8021cee8
// Size: 1532 bytes

/* WARNING: Removing unreachable block (ram,0x8021d4bc) */
/* WARNING: Removing unreachable block (ram,0x8021d4b4) */
/* WARNING: Removing unreachable block (ram,0x8021cf00) */
/* WARNING: Removing unreachable block (ram,0x8021cef8) */

void FUN_8021cee8(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,ushort *param_9)

{
  ushort uVar1;
  ushort uVar2;
  int iVar3;
  uint uVar4;
  short sVar5;
  uint *puVar6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar7;
  float *pfVar8;
  double dVar9;
  undefined8 extraout_f1;
  double dVar10;
  undefined4 local_58;
  uint local_54;
  float local_50;
  float local_4c;
  float local_48;
  float afStack_44 [3];
  undefined4 local_38;
  uint uStack_34;
  
  pfVar8 = *(float **)(param_9 + 0x5c);
  iVar7 = *(int *)(param_9 + 0x26);
  FUN_8002bac4();
  iVar3 = FUN_8021c644((uint)param_9);
  if (iVar3 == 0) {
    if ((*(byte *)(pfVar8 + 0x5e) >> 5 & 1) == 0) {
      uVar4 = FUN_80020078((int)*(short *)(iVar7 + 0x20));
      *(byte *)(pfVar8 + 0x5e) =
           (byte)((uVar4 & 0xff) << 5) & 0x20 | *(byte *)(pfVar8 + 0x5e) & 0xdf;
      pfVar8[0x45] = FLOAT_803e76d4;
      if ((*(byte *)(pfVar8 + 0x5e) >> 5 & 1) != 0) {
        local_58 = 0x2a;
        (**(code **)(*DAT_803dd71c + 0x8c))
                  ((double)FLOAT_803e76e4,pfVar8 + 1,param_9,&local_58,0xffffffff);
        FUN_80010340((double)FLOAT_803e76e8,pfVar8 + 1);
        *(float *)(param_9 + 6) = pfVar8[0x1b];
        *(float *)(param_9 + 8) = pfVar8[0x1c];
        *(float *)(param_9 + 10) = pfVar8[0x1d];
        *pfVar8 = FLOAT_803e76d0;
        FUN_8000bb38((uint)param_9,0x308);
        FUN_8000bb38((uint)param_9,0x30a);
      }
    }
    else {
      if ((*(byte *)((int)pfVar8 + 0x179) >> 3 & 1) == 0) {
        FUN_80035ff8((int)param_9);
        pfVar8[0x44] = *pfVar8;
        FLOAT_803dcf60 = FLOAT_803e76d0 * *pfVar8;
      }
      else {
        FUN_80293900((double)(pfVar8[0x1e] * pfVar8[0x1e] + pfVar8[0x20] * pfVar8[0x20]));
        iVar3 = FUN_80021884();
        param_2 = (double)FLOAT_803e76ec;
        uStack_34 = (int)(short)iVar3 ^ 0x80000000;
        local_38 = 0x43300000;
        dVar9 = (double)FUN_80294964();
        dVar10 = (double)(float)((double)FLOAT_803e7724 * dVar9);
        dVar9 = (double)FUN_802945e0();
        param_4 = (double)(FLOAT_803e7728 * (float)((double)FLOAT_803e772c * dVar9));
        if ((*(byte *)(pfVar8 + 0x5e) >> 6 & 1) != 0) {
          param_2 = (double)*pfVar8;
          if (param_2 < (double)FLOAT_803e76d4) {
            param_2 = -param_2;
          }
          param_3 = (double)pfVar8[0x44];
          if (param_3 < (double)FLOAT_803e76d4) {
            param_3 = -param_3;
          }
          if ((double)(float)((double)FLOAT_803e76d0 + param_2) < param_3) {
            param_4 = (double)(float)(param_4 + (double)FLOAT_803e76d0);
          }
        }
        if ((*(byte *)(pfVar8 + 0x5e) >> 1 & 0xf) != 0) {
          param_4 = (double)(float)(param_4 + (double)FLOAT_803e76d0);
        }
        pfVar8[0x44] = pfVar8[0x45] + (float)((double)pfVar8[0x44] + dVar10);
        dVar10 = (double)pfVar8[0x44];
        dVar9 = dVar10;
        if (dVar10 < (double)FLOAT_803e76d4) {
          dVar9 = -dVar10;
        }
        if (param_4 <= dVar9) {
          dVar9 = param_4;
          if ((double)*pfVar8 < dVar10) {
            dVar9 = -param_4;
          }
          pfVar8[0x44] = (float)((double)pfVar8[0x44] + dVar9);
        }
        else {
          pfVar8[0x44] = *pfVar8;
        }
        FUN_80035eec((int)param_9,8,1,0);
      }
      if (FLOAT_803e76d4 <= pfVar8[0x44]) {
        (**(code **)(*DAT_803dd71c + 0x94))(pfVar8 + 1,0);
      }
      else {
        (**(code **)(*DAT_803dd71c + 0x94))(pfVar8 + 1,1);
      }
      dVar9 = (double)FLOAT_803e76d4;
      pfVar8[0x45] = FLOAT_803e76d4;
      if (dVar9 != (double)pfVar8[0x44]) {
        FUN_80010340((double)pfVar8[0x44],pfVar8 + 1);
        if (((pfVar8[0x21] == 0.0) && (pfVar8[5] != 0.0)) ||
           ((pfVar8[0x21] != 0.0 && (pfVar8[5] == 0.0)))) {
          uVar4 = (uint)*(byte *)((int)pfVar8[0x2a] + 0x18);
          puVar6 = &local_54;
          iVar3 = FUN_8021c778(param_9,(uint)*(byte *)((int)pfVar8[0x29] + 0x18),uVar4,puVar6);
          if (iVar3 != 0) {
            FUN_8021bf40(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         pfVar8 + 1,local_54,uVar4,puVar6,in_r7,in_r8,in_r9,in_r10);
          }
        }
      }
      local_50 = pfVar8[0x1b];
      local_4c = pfVar8[0x1c];
      local_48 = pfVar8[0x1d];
      uStack_34 = (int)*(short *)(pfVar8 + 0x5d) ^ 0x80000000;
      local_38 = 0x43300000;
      dVar9 = (double)FUN_802945e0();
      local_4c = local_4c + (float)((double)FLOAT_803e76e0 + dVar9);
      *(ushort *)(pfVar8 + 0x5d) = *(short *)(pfVar8 + 0x5d) + (ushort)DAT_803dc070 * 800;
      if ((*(byte *)((int)pfVar8 + 0x179) >> 4 & 1) == 0) {
        FUN_80293900((double)(pfVar8[0x1e] * pfVar8[0x1e] + pfVar8[0x20] * pfVar8[0x20]));
        iVar3 = FUN_80021884();
        uVar1 = ((short)iVar3 + -0x8000) - *param_9;
        iVar3 = FUN_80021884();
        param_9[1] = (ushort)iVar3;
        if ((short)uVar1 < -0x800) {
          uVar1 = 0xf800;
        }
        else if (0x800 < (short)uVar1) {
          uVar1 = 0x800;
        }
        uVar2 = uVar1;
        if (FLOAT_803e76d4 <= pfVar8[0x44]) {
          uVar2 = -uVar1;
        }
        param_9[2] = uVar2;
        if ((short)uVar1 < -0x100) {
          uVar1 = 0xff00;
        }
        else if (0x100 < (short)uVar1) {
          uVar1 = 0x100;
        }
        *param_9 = *param_9 + uVar1;
        uVar1 = param_9[1];
        if ((short)uVar1 < -100) {
          uVar1 = 0xff9c;
        }
        else if (100 < (short)uVar1) {
          uVar1 = 100;
        }
        param_9[1] = uVar1;
      }
      else {
        iVar3 = FUN_80036f50(0x45,param_9,(float *)0x0);
        if (iVar3 != 0) {
          iVar3 = FUN_800386e0(param_9,iVar3,(float *)0x0);
          sVar5 = (short)iVar3;
          if (sVar5 < -0x200) {
            sVar5 = -0x200;
          }
          else if (0x200 < sVar5) {
            sVar5 = 0x200;
          }
          *param_9 = *param_9 + sVar5;
          uVar1 = param_9[1];
          if (uVar1 != 0) {
            if ((short)uVar1 < -0x100) {
              uVar1 = 0xff00;
            }
            else if (0x100 < (short)uVar1) {
              uVar1 = 0x100;
            }
            param_9[1] = param_9[1] - uVar1;
          }
          param_9[2] = sVar5 * DAT_803dcf64;
        }
      }
      FUN_80247eb8(&local_50,(float *)(param_9 + 6),afStack_44);
      FUN_80222564((double)FLOAT_803dcf60,
                   (double)(float)((double)FLOAT_803dcf60 / (double)FLOAT_803e7730),
                   (double)FLOAT_803e7734,(int)param_9,(float *)(param_9 + 0x12),afStack_44);
      FUN_80247e94((float *)(param_9 + 6),(float *)(param_9 + 0x12),(float *)(param_9 + 6));
    }
  }
  return;
}

