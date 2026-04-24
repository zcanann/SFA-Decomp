// Function: FUN_80223834
// Entry: 80223834
// Size: 1688 bytes

/* WARNING: Removing unreachable block (ram,0x80223950) */

void FUN_80223834(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  byte bVar1;
  char cVar2;
  uint uVar3;
  float *pfVar4;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int unaff_r30;
  int iVar5;
  
  iVar5 = *(int *)(param_9 + 0xb8);
  uVar3 = (uint)*(byte *)(iVar5 + 0x65a);
  pfVar4 = (float *)(iVar5 + 0x654);
  cVar2 = FUN_8003549c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                       &DAT_8032bb18,1,uVar3,pfVar4,in_r8,in_r9,in_r10);
  *(char *)(iVar5 + 0x65a) = cVar2;
  if (cVar2 == '\0') {
    if ((*(byte *)(iVar5 + 0x65b) < 4) || (8 < *(byte *)(iVar5 + 0x65b))) {
      if (*(short *)(param_9 + 0xa0) != 2) {
        FUN_8003042c((double)FLOAT_803e797c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,2,0,uVar3,pfVar4,in_r8,in_r9,in_r10);
      }
    }
    else if (*(short *)(param_9 + 0xa0) != 0x203) {
      FUN_8003042c((double)FLOAT_803e797c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0x203,0,uVar3,pfVar4,in_r8,in_r9,in_r10);
    }
    cVar2 = *(char *)(iVar5 + 0x600);
    FUN_80115330();
    if ((((3 < *(byte *)(iVar5 + 0x65b)) && (*(byte *)(iVar5 + 0x65b) < 8)) && (cVar2 != '\x01')) &&
       (*(char *)(iVar5 + 0x600) == '\x01')) {
      FUN_8000bb38(param_9,0x3e6);
    }
    FUN_8003b408(param_9,iVar5 + 0x624);
    if ((*(byte *)(iVar5 + 0x659) & 1) == 0) {
      bVar1 = *(byte *)(iVar5 + 0x658);
      if (bVar1 != 1) {
        if (bVar1 == 0) {
          if ((*(byte *)(param_9 + 0xaf) & 1) != 0) {
            FUN_80014b68(0,0x100);
            FUN_800201ac(0x7fb,1);
            *(undefined *)(iVar5 + 0x658) = 2;
            *(byte *)(iVar5 + 0x659) = *(byte *)(iVar5 + 0x659) | 1;
          }
        }
        else if ((bVar1 < 3) && ((*(byte *)(param_9 + 0xaf) & 1) != 0)) {
          switch(*(undefined *)(iVar5 + 0x65b)) {
          case 0:
            cVar2 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_9 + 0xac));
            if (cVar2 == '\x02') {
              if (*(char *)(iVar5 + 0x65c) == '\x14') {
                unaff_r30 = 0x15;
              }
              else {
                unaff_r30 = 0x14;
              }
            }
            else {
              uVar3 = FUN_80020078(0xc90);
              if (uVar3 == 0) {
                uVar3 = FUN_80020078(0xc36);
                if (uVar3 == 0) {
                  uVar3 = FUN_80020078(0xc55);
                  if (uVar3 == 0) {
                    uVar3 = FUN_80020078(0x7fc);
                    if (uVar3 == 0) {
                      if (*(char *)(iVar5 + 0x65c) == '\0') {
                        unaff_r30 = 1;
                      }
                      else if (*(char *)(iVar5 + 0x65c) == '\x01') {
                        unaff_r30 = 2;
                      }
                      else {
                        unaff_r30 = 0;
                      }
                    }
                    else {
                      unaff_r30 = 3;
                    }
                  }
                  else {
                    unaff_r30 = 3;
                  }
                }
                else {
                  unaff_r30 = 4;
                }
              }
              else {
                unaff_r30 = 5;
              }
            }
            break;
          case 1:
            cVar2 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_9 + 0xac));
            if (cVar2 == '\x02') {
              uVar3 = FUN_80020078(0xc92);
              if (uVar3 == 0) {
                uVar3 = FUN_80020078(0x235);
                if (uVar3 == 0) {
                  unaff_r30 = 8;
                }
                else {
                  unaff_r30 = 9;
                }
              }
              else {
                *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
                unaff_r30 = -1;
              }
            }
            else {
              uVar3 = FUN_80020078(0xc90);
              if (uVar3 == 0) {
                uVar3 = FUN_80020078(0xc36);
                if (uVar3 == 0) {
                  uVar3 = FUN_80020078(0xc55);
                  if (uVar3 == 0) {
                    unaff_r30 = 0;
                  }
                  else {
                    unaff_r30 = 5;
                  }
                }
                else {
                  unaff_r30 = 6;
                }
              }
              else {
                unaff_r30 = 7;
              }
            }
            break;
          case 2:
            unaff_r30 = 0;
            break;
          case 3:
            unaff_r30 = 0;
            break;
          case 4:
            unaff_r30 = 0;
            break;
          case 5:
            unaff_r30 = 1;
            break;
          case 6:
            unaff_r30 = 2;
            break;
          case 7:
            unaff_r30 = 3;
            break;
          case 8:
            uVar3 = FUN_80020078(0x9ad);
            if (uVar3 == 0) {
              unaff_r30 = 4;
              FUN_80014b68(0,0x100);
              FUN_800201ac(0x9ad,1);
            }
            else {
              unaff_r30 = 0;
            }
            break;
          case 9:
            cVar2 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_9 + 0xac));
            if (cVar2 == '\x02') {
              if (*(char *)(iVar5 + 0x65c) == '\x16') {
                unaff_r30 = 0x17;
              }
              else {
                unaff_r30 = 0x16;
              }
            }
            else {
              uVar3 = FUN_80020078(0xc90);
              if (uVar3 == 0) {
                uVar3 = FUN_80020078(0xc36);
                if (uVar3 == 0) {
                  uVar3 = FUN_80020078(0xc55);
                  if (uVar3 == 0) {
                    uVar3 = FUN_80020078(0x7fc);
                    if (uVar3 == 0) {
                      if (*(char *)(iVar5 + 0x65c) == '\x06') {
                        unaff_r30 = 7;
                      }
                      else {
                        unaff_r30 = 6;
                      }
                    }
                    else {
                      unaff_r30 = 8;
                    }
                  }
                  else {
                    unaff_r30 = 8;
                  }
                }
                else {
                  unaff_r30 = 9;
                }
              }
              else {
                unaff_r30 = 10;
              }
            }
            break;
          case 10:
            cVar2 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_9 + 0xac));
            if (cVar2 == '\x02') {
              cVar2 = *(char *)(iVar5 + 0x65c);
              if (cVar2 == '\x18') {
                unaff_r30 = 0x19;
              }
              else if (cVar2 == '\x19') {
                unaff_r30 = 0x1a;
              }
              else if (cVar2 == '\x1a') {
                unaff_r30 = 0x1b;
              }
              else {
                unaff_r30 = 0x18;
              }
            }
            else {
              uVar3 = FUN_80020078(0xc90);
              if (uVar3 == 0) {
                uVar3 = FUN_80020078(0xc36);
                if (uVar3 == 0) {
                  uVar3 = FUN_80020078(0xc55);
                  if (uVar3 == 0) {
                    uVar3 = FUN_80020078(0x7fc);
                    if (uVar3 != 0) {
                      if (*(char *)(iVar5 + 0x65c) == '\v') {
                        unaff_r30 = 0xc;
                      }
                      else {
                        unaff_r30 = 0xb;
                      }
                    }
                  }
                  else {
                    unaff_r30 = 0xd;
                  }
                }
                else {
                  unaff_r30 = 0xe;
                }
              }
              else {
                unaff_r30 = 0xf;
              }
            }
            break;
          case 0xb:
            cVar2 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_9 + 0xac));
            if (cVar2 == '\x02') {
              cVar2 = *(char *)(iVar5 + 0x65c);
              if (cVar2 == '\x1c') {
                unaff_r30 = 0x1d;
              }
              else if (cVar2 == '\x1d') {
                unaff_r30 = 0x1e;
              }
              else if (cVar2 == '\x1e') {
                unaff_r30 = 0x1f;
              }
              else {
                unaff_r30 = 0x1c;
              }
            }
            else {
              uVar3 = FUN_80020078(0xc90);
              if (uVar3 == 0) {
                uVar3 = FUN_80020078(0xc36);
                if (uVar3 == 0) {
                  uVar3 = FUN_80020078(0xc55);
                  if (uVar3 == 0) {
                    uVar3 = FUN_80020078(0x7fc);
                    if (uVar3 != 0) {
                      unaff_r30 = 0x10;
                    }
                  }
                  else {
                    unaff_r30 = 0x10;
                  }
                }
                else if (*(char *)(iVar5 + 0x65c) == '\x11') {
                  unaff_r30 = 0x12;
                }
                else {
                  unaff_r30 = 0x11;
                }
              }
              else {
                unaff_r30 = 0x13;
              }
            }
          }
          if (unaff_r30 != -1) {
            FUN_80014b68(0,0x100);
            (**(code **)(*DAT_803dd6d4 + 0x48))(unaff_r30,param_9,0xffffffff);
            *(char *)(iVar5 + 0x65c) = (char)unaff_r30;
          }
        }
      }
      FUN_8002fb40((double)FLOAT_803e7974,(double)FLOAT_803dc074);
    }
  }
  return;
}

