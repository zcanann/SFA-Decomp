// Function: FUN_800e9020
// Entry: 800e9020
// Size: 604 bytes

void FUN_800e9020(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  uint uVar5;
  byte *pbVar6;
  uint uVar7;
  double extraout_f1;
  double dVar8;
  undefined auStack_708 [28];
  undefined auStack_6ec [5];
  char local_6e7;
  byte local_1b0 [5];
  byte local_1ab;
  byte local_1aa;
  float local_1a8;
  
  uVar1 = FUN_8028683c();
  uVar7 = 0;
  dVar8 = extraout_f1;
  do {
    iVar2 = FUN_8007ddd8(dVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar7 & 0xff,
                         auStack_708);
    if (iVar2 == 0) break;
    *(char *)(uVar1 + 0x20) = local_6e7;
    if (local_6e7 == '\0') {
      FUN_800033a8(uVar1,0,0x24);
    }
    else {
      uVar4 = 4;
      FUN_80003494(uVar1,(uint)auStack_6ec,4);
      *(char *)(uVar1 + 4) = (char)(((uint)local_1ab * 100) / 0xbb);
      if (local_1ab < 0xb4) {
        if (local_1ab < 0xb1) {
          if (local_1ab < 0xa2) {
            if (local_1ab < 0x8b) {
              if (local_1ab < 0x82) {
                if (local_1ab < 0x72) {
                  if (local_1ab < 99) {
                    if (local_1ab < 0x49) {
                      if (local_1ab < 0x3e) {
                        if (local_1ab < 9) {
                          *(undefined *)(uVar1 + 5) = 0;
                          *(undefined *)(uVar1 + 6) = 0;
                        }
                        else {
                          *(undefined *)(uVar1 + 5) = 1;
                          *(undefined *)(uVar1 + 6) = 0;
                        }
                      }
                      else {
                        *(undefined *)(uVar1 + 5) = 1;
                        *(undefined *)(uVar1 + 6) = 1;
                      }
                    }
                    else {
                      *(undefined *)(uVar1 + 5) = 2;
                      *(undefined *)(uVar1 + 6) = 1;
                    }
                  }
                  else {
                    *(undefined *)(uVar1 + 5) = 2;
                    *(undefined *)(uVar1 + 6) = 2;
                  }
                }
                else {
                  *(undefined *)(uVar1 + 5) = 3;
                  *(undefined *)(uVar1 + 6) = 2;
                }
              }
              else {
                *(undefined *)(uVar1 + 5) = 3;
                *(undefined *)(uVar1 + 6) = 3;
              }
            }
            else {
              *(undefined *)(uVar1 + 5) = 4;
              *(undefined *)(uVar1 + 6) = 3;
            }
          }
          else {
            *(undefined *)(uVar1 + 5) = 4;
            *(undefined *)(uVar1 + 6) = 4;
          }
        }
        else {
          *(undefined *)(uVar1 + 5) = 5;
          *(undefined *)(uVar1 + 6) = 4;
        }
      }
      else {
        *(undefined *)(uVar1 + 5) = 6;
        *(undefined *)(uVar1 + 6) = 4;
      }
      dVar8 = (double)(local_1a8 / FLOAT_803e134c);
      iVar2 = FUN_80286718(dVar8);
      *(int *)(uVar1 + 8) = iVar2;
      *(undefined4 *)(uVar1 + 0xc) = 0;
      *(undefined4 *)(uVar1 + 0x10) = 0;
      *(undefined4 *)(uVar1 + 0x14) = 0;
      *(undefined4 *)(uVar1 + 0x18) = 0;
      *(undefined4 *)(uVar1 + 0x1c) = 0;
      pbVar6 = local_1b0;
      uVar5 = uVar1;
      for (iVar2 = 0; iVar2 < (int)(uint)local_1aa; iVar2 = iVar2 + 1) {
        uVar3 = FUN_800191fc(dVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                             *pbVar6 + 0xf4,0,uVar4,in_r6,in_r7,in_r8,in_r9,in_r10);
        *(undefined4 *)(uVar5 + 0xc) = uVar3;
        uVar5 = uVar5 + 4;
        pbVar6 = pbVar6 + 1;
      }
      *(undefined *)(uVar1 + 0x21) = 0;
      *(char *)(uVar1 + 0x20) = local_6e7;
    }
    uVar1 = uVar1 + 0x24;
    uVar7 = uVar7 + 1;
  } while ((int)uVar7 < 3);
  FUN_80286888();
  return;
}

