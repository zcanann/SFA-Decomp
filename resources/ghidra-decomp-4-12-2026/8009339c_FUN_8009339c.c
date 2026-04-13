// Function: FUN_8009339c
// Entry: 8009339c
// Size: 2324 bytes

/* WARNING: Removing unreachable block (ram,0x8009356c) */

void FUN_8009339c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,int param_10,int param_11,undefined4 param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  byte bVar1;
  char cVar2;
  ushort uVar3;
  double dVar4;
  undefined4 *puVar5;
  uint uVar6;
  int iVar7;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  ushort local_44 [4];
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;
  
  local_50 = DAT_802c2728;
  local_4c = DAT_802c272c;
  local_48 = DAT_802c2730;
  local_5c = DAT_802c2734;
  local_58 = DAT_802c2738;
  local_54 = DAT_802c273c;
  puVar5 = FUN_800e877c();
  if (param_11 != 0) {
    if (param_9 != (ushort *)0x0) {
      local_50 = *(float *)(param_9 + 0xc);
      local_4c = *(float *)(param_9 + 0xe);
      local_48 = *(float *)(param_9 + 0x10);
    }
    if (param_10 != 0) {
      local_5c = *(float *)(param_10 + 0x18);
      local_58 = *(float *)(param_10 + 0x1c);
      local_54 = *(float *)(param_10 + 0x20);
    }
    uVar6 = (uint)*(ushort *)(param_11 + 0x26);
    if (uVar6 < 9) {
      iVar7 = (&DAT_8039b488)[uVar6];
      if (iVar7 != 0) {
        if (iVar7 != 0) {
          bVar1 = *(byte *)(param_11 + 0x58);
          if ((bVar1 & 2) == 0) {
            if (((bVar1 & 8) == 0) || (*(char *)(iVar7 + 0x144e) == '\0')) {
              if ((bVar1 & 0x20) == 0) {
                if ((bVar1 & 4) != 0) {
                  if (*(char *)(iVar7 + 0x144f) != '\0') {
                    *(undefined *)(iVar7 + 0x144f) = 0;
                  }
                  *(int *)((&DAT_8039b488)[*(ushort *)(param_11 + 0x26)] + 0x13f8) =
                       1 - *(int *)((&DAT_8039b488)[*(ushort *)(param_11 + 0x26)] + 0x13f8);
                  if (*(ushort *)(param_11 + 0x2a) == 0) {
                    local_18 = (double)CONCAT44(0x43300000,
                                                *(int *)((&DAT_8039b488)
                                                         [*(ushort *)(param_11 + 0x26)] + 0x13fc) -
                                                1U ^ 0x80000000);
                    *(float *)((&DAT_8039b488)[*(ushort *)(param_11 + 0x26)] + 0x142c) =
                         (float)(local_18 - DOUBLE_803dfe28);
                  }
                  else {
                    local_18 = (double)CONCAT44(0x43300000,
                                                *(uint *)((&DAT_8039b488)
                                                          [*(ushort *)(param_11 + 0x26)] + 0x13fc) ^
                                                0x80000000);
                    local_20 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(param_11 + 0x2a));
                    *(float *)((&DAT_8039b488)[*(ushort *)(param_11 + 0x26)] + 0x142c) =
                         (float)(local_18 - DOUBLE_803dfe28) / (float)(local_20 - DOUBLE_803dfe30);
                  }
                  if (*(ushort *)(param_11 + 0x2c) == 0) {
                    local_18 = (double)CONCAT44(0x43300000,
                                                -(*(int *)((&DAT_8039b488)
                                                           [*(ushort *)(param_11 + 0x26)] + 0x13fc)
                                                 + -1) ^ 0x80000000);
                    *(float *)((&DAT_8039b488)[*(ushort *)(param_11 + 0x26)] + 0x1430) =
                         (float)(local_18 - DOUBLE_803dfe28);
                  }
                  else {
                    local_18 = (double)CONCAT44(0x43300000,
                                                *(uint *)((&DAT_8039b488)
                                                          [*(ushort *)(param_11 + 0x26)] + 0x13fc) ^
                                                0x80000000);
                    local_20 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(param_11 + 0x2c));
                    *(float *)((&DAT_8039b488)[*(ushort *)(param_11 + 0x26)] + 0x1430) =
                         -((float)(local_18 - DOUBLE_803dfe28) / (float)(local_20 - DOUBLE_803dfe30)
                          );
                  }
                }
              }
              else {
                FUN_800930f0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar6,0
                             ,iVar7,(uint)bVar1,param_13,param_14,param_15,param_16);
              }
            }
            else {
              *(undefined *)((int)puVar5 + uVar6 + 0x41) = *(undefined *)(iVar7 + 0x144d);
              *(char *)((&DAT_8039b488)[*(ushort *)(param_11 + 0x26)] + 0x144d) =
                   '\x01' - *(char *)((&DAT_8039b488)[*(ushort *)(param_11 + 0x26)] + 0x144d);
              iVar7 = (&DAT_8039b488)[*(ushort *)(param_11 + 0x26)];
              if (*(char *)(iVar7 + 0x144d) == '\x01') {
                local_68 = FLOAT_803dfe20;
                local_64 = FLOAT_803dfe20;
                local_60 = FLOAT_803dfe20;
                local_38 = FLOAT_803dfe20;
                local_34 = FLOAT_803dfe20;
                local_30 = FLOAT_803dfe20;
                local_3c = FLOAT_803dfe24;
                local_44[2] = 0;
                local_44[1] = 0;
                local_44[0] = *param_9;
                FUN_80021b8c(local_44,&local_68);
                *(float *)((&DAT_8039b488)[*(ushort *)(param_11 + 0x26)] + 0x140c) =
                     local_68 + *(float *)(param_9 + 0xc);
                *(float *)((&DAT_8039b488)[*(ushort *)(param_11 + 0x26)] + 0x1410) =
                     local_64 + *(float *)(param_9 + 0xe);
                *(float *)((&DAT_8039b488)[*(ushort *)(param_11 + 0x26)] + 0x1414) =
                     local_60 + *(float *)(param_9 + 0x10);
                if (FLOAT_803dfefc <
                    *(float *)((&DAT_8039b488)[*(ushort *)(param_11 + 0x26)] + 0x1438)) {
                  FUN_8000a538(*(int **)(&DAT_80310160 +
                                        *(int *)((&DAT_8039b488)[*(ushort *)(param_11 + 0x26)] +
                                                0x13f4) * 4),0);
                }
              }
              else if (FLOAT_803dfefc < *(float *)(iVar7 + 0x1438)) {
                FUN_8000a538(*(int **)(&DAT_80310160 + *(int *)(iVar7 + 0x13f4) * 4),1);
              }
              if (*(char *)((int)puVar5 + *(ushort *)(param_11 + 0x26) + 0x41) == '\0') {
                puVar5[(uint)*(ushort *)(param_11 + 0x26) * 3 + 5] = (int)local_50;
                puVar5[(uint)*(ushort *)(param_11 + 0x26) * 3 + 6] = (int)local_4c;
                puVar5[(uint)*(ushort *)(param_11 + 0x26) * 3 + 7] = (int)local_48;
              }
            }
          }
        }
      }
      else {
        bVar1 = *(byte *)(param_11 + 0x58);
        if ((((bVar1 & 4) == 0) && ((bVar1 & 8) == 0)) && ((bVar1 & 0x20) == 0)) {
          if ((((bVar1 & 2) == 0) || ((bVar1 & 0x10) == 0)) || (*(char *)(param_11 + 0x5d) == '\0'))
          {
            if (((bVar1 & 2) == 0) || ((bVar1 & 0x10) == 0)) {
              if ((bVar1 & 2) != 0) {
                FUN_80091c54((double)local_50,(double)local_4c,(double)local_48,param_4,param_5,
                             param_6,param_7,param_8,param_11,param_10,0,param_12,param_13,param_14,
                             param_15,param_16);
              }
            }
            else {
              FUN_80091c54((double)local_5c,(double)local_58,(double)local_54,param_4,param_5,
                           param_6,param_7,param_8,param_11,param_10,0,param_12,param_13,param_14,
                           param_15,param_16);
            }
          }
          else {
            FUN_80091c54((double)local_50,(double)local_4c,(double)local_48,param_4,param_5,param_6,
                         param_7,param_8,param_11,param_10,0,param_12,param_13,param_14,param_15,
                         param_16);
          }
        }
        if (((*(byte *)(param_11 + 0x58) & 2) != 0) &&
           ((*(char *)(param_11 + 0x5c) == '\0' || (*(char *)(param_11 + 0x5c) == '\x04')))) {
          uVar3 = *(ushort *)(param_11 + 0x26);
          if (uVar3 == 1) {
            *(short *)(puVar5 + 4) = *(short *)(param_11 + 0x24) + -1;
            puVar5[8] = (int)local_50;
            puVar5[9] = (int)local_4c;
            puVar5[10] = (int)local_48;
            cVar2 = *(char *)((int)puVar5 + *(ushort *)(param_11 + 0x26) + 0x41);
            if (cVar2 != -1) {
              *(char *)((&DAT_8039b488)[*(ushort *)(param_11 + 0x26)] + 0x144d) = '\x01' - cVar2;
              dVar4 = DOUBLE_803dfe28;
              uVar6 = (uint)*(ushort *)(param_11 + 0x26);
              if (*(char *)((int)puVar5 + uVar6 + 0x41) == '\0') {
                local_18 = (double)CONCAT44(0x43300000,puVar5[uVar6 * 3 + 5] ^ 0x80000000);
                *(float *)((&DAT_8039b488)[uVar6] + 0x140c) = (float)(local_18 - DOUBLE_803dfe28);
                local_20 = (double)CONCAT44(0x43300000,
                                            puVar5[(uint)*(ushort *)(param_11 + 0x26) * 3 + 6] ^
                                            0x80000000);
                *(float *)((&DAT_8039b488)[*(ushort *)(param_11 + 0x26)] + 0x1410) =
                     (float)(local_20 - dVar4);
                local_28 = (double)CONCAT44(0x43300000,
                                            puVar5[(uint)*(ushort *)(param_11 + 0x26) * 3 + 7] ^
                                            0x80000000);
                *(float *)((&DAT_8039b488)[*(ushort *)(param_11 + 0x26)] + 0x1414) =
                     (float)(local_28 - dVar4);
              }
            }
          }
          else if (uVar3 == 0) {
            *(short *)((int)puVar5 + 0xe) = *(short *)(param_11 + 0x24) + -1;
            puVar5[5] = (int)local_50;
            puVar5[6] = (int)local_4c;
            puVar5[7] = (int)local_48;
            cVar2 = *(char *)((int)puVar5 + *(ushort *)(param_11 + 0x26) + 0x41);
            if (cVar2 != -1) {
              *(char *)((&DAT_8039b488)[*(ushort *)(param_11 + 0x26)] + 0x144d) = '\x01' - cVar2;
              dVar4 = DOUBLE_803dfe28;
              uVar6 = (uint)*(ushort *)(param_11 + 0x26);
              if (*(char *)((int)puVar5 + uVar6 + 0x41) == '\0') {
                local_18 = (double)CONCAT44(0x43300000,puVar5[uVar6 * 3 + 5] ^ 0x80000000);
                *(float *)((&DAT_8039b488)[uVar6] + 0x140c) = (float)(local_18 - DOUBLE_803dfe28);
                local_20 = (double)CONCAT44(0x43300000,
                                            puVar5[(uint)*(ushort *)(param_11 + 0x26) * 3 + 6] ^
                                            0x80000000);
                *(float *)((&DAT_8039b488)[*(ushort *)(param_11 + 0x26)] + 0x1410) =
                     (float)(local_20 - dVar4);
                local_28 = (double)CONCAT44(0x43300000,
                                            puVar5[(uint)*(ushort *)(param_11 + 0x26) * 3 + 7] ^
                                            0x80000000);
                *(float *)((&DAT_8039b488)[*(ushort *)(param_11 + 0x26)] + 0x1414) =
                     (float)(local_28 - dVar4);
              }
            }
          }
          else if (uVar3 < 3) {
            *(short *)((int)puVar5 + 0x12) = *(short *)(param_11 + 0x24) + -1;
            puVar5[0xb] = (int)local_50;
            puVar5[0xc] = (int)local_4c;
            puVar5[0xd] = (int)local_48;
            cVar2 = *(char *)((int)puVar5 + *(ushort *)(param_11 + 0x26) + 0x41);
            if (cVar2 != -1) {
              *(char *)((&DAT_8039b488)[*(ushort *)(param_11 + 0x26)] + 0x144d) = '\x01' - cVar2;
              dVar4 = DOUBLE_803dfe28;
              uVar6 = (uint)*(ushort *)(param_11 + 0x26);
              if (*(char *)((int)puVar5 + uVar6 + 0x41) == '\0') {
                local_18 = (double)CONCAT44(0x43300000,puVar5[uVar6 * 3 + 5] ^ 0x80000000);
                *(float *)((&DAT_8039b488)[uVar6] + 0x140c) = (float)(local_18 - DOUBLE_803dfe28);
                local_20 = (double)CONCAT44(0x43300000,
                                            puVar5[(uint)*(ushort *)(param_11 + 0x26) * 3 + 6] ^
                                            0x80000000);
                *(float *)((&DAT_8039b488)[*(ushort *)(param_11 + 0x26)] + 0x1410) =
                     (float)(local_20 - dVar4);
                local_28 = (double)CONCAT44(0x43300000,
                                            puVar5[(uint)*(ushort *)(param_11 + 0x26) * 3 + 7] ^
                                            0x80000000);
                *(float *)((&DAT_8039b488)[*(ushort *)(param_11 + 0x26)] + 0x1414) =
                     (float)(local_28 - dVar4);
              }
            }
          }
        }
      }
    }
  }
  return;
}

