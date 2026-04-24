// Function: FUN_80155960
// Entry: 80155960
// Size: 700 bytes

void FUN_80155960(int *param_1,int param_2)

{
  float fVar1;
  float fVar2;
  char cVar3;
  int iVar4;
  float *pfVar5;
  double dVar6;
  float local_d0;
  float local_cc;
  float local_c8;
  float local_c4 [2];
  float local_bc;
  float local_b8;
  float local_b4;
  float local_b0;
  float afStack_ac [3];
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float afStack_88 [3];
  float local_7c;
  int local_78;
  float local_74;
  float local_70;
  int local_6c;
  float local_68;
  int iStack_64;
  undefined4 local_60;
  float local_5c;
  float local_58;
  float local_54;
  undefined4 local_50;
  float local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  float local_28;
  float local_24;
  float local_20;
  
  cVar3 = '\0';
  pfVar5 = (float *)&DAT_8031ff48;
  for (iVar4 = 0; (fVar2 = FLOAT_803e36bc, fVar1 = FLOAT_803e36b8, cVar3 == '\0' && (iVar4 < 4));
      iVar4 = iVar4 + 1) {
    local_70 = (float)param_1[3] + *pfVar5;
    local_78 = param_1[4];
    local_68 = (float)param_1[5] + pfVar5[1];
    local_7c = (float)param_1[3] - *pfVar5;
    local_74 = (float)param_1[5] - pfVar5[1];
    local_6c = local_78;
    cVar3 = FUN_80064248(&local_70,&local_7c,(float *)0x3,&iStack_64,param_1,5,3,0xff,0);
    pfVar5 = pfVar5 + 2;
  }
  if (cVar3 != '\0') {
    param_1[3] = (int)((local_20 - FLOAT_803e36b8) * ((local_7c - local_70) / FLOAT_803e36bc) +
                      local_70);
    param_1[5] = (int)((local_20 - fVar1) * ((local_74 - local_68) / fVar2) + local_68);
    *(undefined4 *)(param_2 + 0x344) = local_48;
    *(undefined4 *)(param_2 + 0x348) = local_44;
    *(undefined4 *)(param_2 + 0x34c) = local_40;
    *(undefined4 *)(param_2 + 0x350) = local_3c;
    if (local_54 < local_58) {
      local_54 = local_58;
    }
    *(float *)(param_2 + 0x358) = local_54;
    if (local_28 < local_24) {
      local_24 = local_28;
    }
    *(float *)(param_2 + 0x35c) = local_24;
    local_a0 = FLOAT_803e3698;
    local_9c = FLOAT_803e369c;
    local_98 = FLOAT_803e3698;
    FUN_80247fb0(&local_a0,(float *)(param_2 + 0x344),afStack_88);
    FUN_80247ef8(afStack_88,afStack_88);
    *(undefined4 *)(param_2 + 0x360) = local_60;
    *(undefined4 *)(param_2 + 0x364) = local_50;
    local_94 = local_5c;
    local_8c = local_4c;
    local_b8 = *(float *)(param_2 + 0x360);
    local_b4 = *(float *)(param_2 + 0x358);
    local_b0 = *(float *)(param_2 + 0x364);
    FUN_80247eb8(&local_b8,&local_94,afStack_ac);
    dVar6 = FUN_80247f90(afStack_ac,(float *)(param_2 + 0x344));
    local_b8 = (float)((double)*(float *)(param_2 + 0x344) * dVar6 + (double)local_94);
    local_b4 = (float)((double)*(float *)(param_2 + 0x348) * dVar6 + (double)local_90);
    local_b0 = (float)((double)*(float *)(param_2 + 0x34c) * dVar6 + (double)local_8c);
    local_d0 = FLOAT_803e3698;
    local_cc = FLOAT_803e369c;
    local_c8 = FLOAT_803e3698;
    FUN_80247fb0(&local_d0,(float *)(param_2 + 0x344),local_c4);
    FUN_80247ef8(local_c4,local_c4);
    if (FLOAT_803e3698 == local_c4[0]) {
      *(float *)(param_2 + 0x354) = (local_8c - *(float *)(param_2 + 0x364)) / local_bc;
    }
    else {
      *(float *)(param_2 + 0x354) = (local_94 - *(float *)(param_2 + 0x360)) / local_c4[0];
    }
    *(undefined *)(param_2 + 0x33a) = 1;
  }
  return;
}

