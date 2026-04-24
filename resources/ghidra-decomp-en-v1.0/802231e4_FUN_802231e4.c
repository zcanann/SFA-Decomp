// Function: FUN_802231e4
// Entry: 802231e4
// Size: 1688 bytes

/* WARNING: Removing unreachable block (ram,0x80223300) */

void FUN_802231e4(int param_1)

{
  byte bVar1;
  char cVar3;
  int iVar2;
  int unaff_r30;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  cVar3 = FUN_800353a4(param_1,&DAT_8032aec0,1,*(undefined *)(iVar4 + 0x65a),iVar4 + 0x654);
  *(char *)(iVar4 + 0x65a) = cVar3;
  if (cVar3 == '\0') {
    if ((*(byte *)(iVar4 + 0x65b) < 4) || (8 < *(byte *)(iVar4 + 0x65b))) {
      if (*(short *)(param_1 + 0xa0) != 2) {
        FUN_80030334((double)FLOAT_803e6ce4,param_1,2,0);
      }
    }
    else if (*(short *)(param_1 + 0xa0) != 0x203) {
      FUN_80030334((double)FLOAT_803e6ce4,param_1,0x203,0);
    }
    cVar3 = *(char *)(iVar4 + 0x600);
    FUN_80115094(param_1,iVar4);
    if ((((3 < *(byte *)(iVar4 + 0x65b)) && (*(byte *)(iVar4 + 0x65b) < 8)) && (cVar3 != '\x01')) &&
       (*(char *)(iVar4 + 0x600) == '\x01')) {
      FUN_8000bb18(param_1,0x3e6);
    }
    FUN_8003b310(param_1,iVar4 + 0x624);
    if ((*(byte *)(iVar4 + 0x659) & 1) == 0) {
      bVar1 = *(byte *)(iVar4 + 0x658);
      if (bVar1 != 1) {
        if (bVar1 == 0) {
          if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
            FUN_80014b3c(0,0x100);
            FUN_800200e8(0x7fb,1);
            *(undefined *)(iVar4 + 0x658) = 2;
            *(byte *)(iVar4 + 0x659) = *(byte *)(iVar4 + 0x659) | 1;
          }
        }
        else if ((bVar1 < 3) && ((*(byte *)(param_1 + 0xaf) & 1) != 0)) {
          switch(*(undefined *)(iVar4 + 0x65b)) {
          case 0:
            cVar3 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(param_1 + 0xac));
            if (cVar3 == '\x02') {
              if (*(char *)(iVar4 + 0x65c) == '\x14') {
                unaff_r30 = 0x15;
              }
              else {
                unaff_r30 = 0x14;
              }
            }
            else {
              iVar2 = FUN_8001ffb4(0xc90);
              if (iVar2 == 0) {
                iVar2 = FUN_8001ffb4(0xc36);
                if (iVar2 == 0) {
                  iVar2 = FUN_8001ffb4(0xc55);
                  if (iVar2 == 0) {
                    iVar2 = FUN_8001ffb4(0x7fc);
                    if (iVar2 == 0) {
                      if (*(char *)(iVar4 + 0x65c) == '\0') {
                        unaff_r30 = 1;
                      }
                      else if (*(char *)(iVar4 + 0x65c) == '\x01') {
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
            cVar3 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(param_1 + 0xac));
            if (cVar3 == '\x02') {
              iVar2 = FUN_8001ffb4(0xc92);
              if (iVar2 == 0) {
                iVar2 = FUN_8001ffb4(0x235);
                if (iVar2 == 0) {
                  unaff_r30 = 8;
                }
                else {
                  unaff_r30 = 9;
                }
              }
              else {
                *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
                unaff_r30 = -1;
              }
            }
            else {
              iVar2 = FUN_8001ffb4(0xc90);
              if (iVar2 == 0) {
                iVar2 = FUN_8001ffb4(0xc36);
                if (iVar2 == 0) {
                  iVar2 = FUN_8001ffb4(0xc55);
                  if (iVar2 == 0) {
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
            iVar2 = FUN_8001ffb4(0x9ad);
            if (iVar2 == 0) {
              unaff_r30 = 4;
              FUN_80014b3c(0,0x100);
              FUN_800200e8(0x9ad,1);
            }
            else {
              unaff_r30 = 0;
            }
            break;
          case 9:
            cVar3 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(param_1 + 0xac));
            if (cVar3 == '\x02') {
              if (*(char *)(iVar4 + 0x65c) == '\x16') {
                unaff_r30 = 0x17;
              }
              else {
                unaff_r30 = 0x16;
              }
            }
            else {
              iVar2 = FUN_8001ffb4(0xc90);
              if (iVar2 == 0) {
                iVar2 = FUN_8001ffb4(0xc36);
                if (iVar2 == 0) {
                  iVar2 = FUN_8001ffb4(0xc55);
                  if (iVar2 == 0) {
                    iVar2 = FUN_8001ffb4(0x7fc);
                    if (iVar2 == 0) {
                      if (*(char *)(iVar4 + 0x65c) == '\x06') {
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
            cVar3 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(param_1 + 0xac));
            if (cVar3 == '\x02') {
              cVar3 = *(char *)(iVar4 + 0x65c);
              if (cVar3 == '\x18') {
                unaff_r30 = 0x19;
              }
              else if (cVar3 == '\x19') {
                unaff_r30 = 0x1a;
              }
              else if (cVar3 == '\x1a') {
                unaff_r30 = 0x1b;
              }
              else {
                unaff_r30 = 0x18;
              }
            }
            else {
              iVar2 = FUN_8001ffb4(0xc90);
              if (iVar2 == 0) {
                iVar2 = FUN_8001ffb4(0xc36);
                if (iVar2 == 0) {
                  iVar2 = FUN_8001ffb4(0xc55);
                  if (iVar2 == 0) {
                    iVar2 = FUN_8001ffb4(0x7fc);
                    if (iVar2 != 0) {
                      if (*(char *)(iVar4 + 0x65c) == '\v') {
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
            cVar3 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(param_1 + 0xac));
            if (cVar3 == '\x02') {
              cVar3 = *(char *)(iVar4 + 0x65c);
              if (cVar3 == '\x1c') {
                unaff_r30 = 0x1d;
              }
              else if (cVar3 == '\x1d') {
                unaff_r30 = 0x1e;
              }
              else if (cVar3 == '\x1e') {
                unaff_r30 = 0x1f;
              }
              else {
                unaff_r30 = 0x1c;
              }
            }
            else {
              iVar2 = FUN_8001ffb4(0xc90);
              if (iVar2 == 0) {
                iVar2 = FUN_8001ffb4(0xc36);
                if (iVar2 == 0) {
                  iVar2 = FUN_8001ffb4(0xc55);
                  if (iVar2 == 0) {
                    iVar2 = FUN_8001ffb4(0x7fc);
                    if (iVar2 != 0) {
                      unaff_r30 = 0x10;
                    }
                  }
                  else {
                    unaff_r30 = 0x10;
                  }
                }
                else if (*(char *)(iVar4 + 0x65c) == '\x11') {
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
            FUN_80014b3c(0,0x100);
            (**(code **)(*DAT_803dca54 + 0x48))(unaff_r30,param_1,0xffffffff);
            *(char *)(iVar4 + 0x65c) = (char)unaff_r30;
          }
        }
      }
      FUN_8002fa48((double)FLOAT_803e6cdc,(double)FLOAT_803db414,param_1,0);
    }
  }
  return;
}

