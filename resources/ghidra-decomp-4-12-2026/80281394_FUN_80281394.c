// Function: FUN_80281394
// Entry: 80281394
// Size: 972 bytes

void FUN_80281394(void)

{
  int *piVar1;
  uint uVar2;
  int iVar3;
  undefined uVar4;
  int *piVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30 [3];
  
  if (DAT_803defd0 == '\0') {
    DAT_803defeb = 0;
    dVar7 = (double)FLOAT_803e8518;
    DAT_803defd0 = '\x03';
    dVar8 = (double)FLOAT_803e855c;
    DAT_803defec = 0;
    dVar9 = (double)FLOAT_803e853c;
    DAT_803defed = 0;
    piVar1 = DAT_803defd4;
LAB_80281724:
    piVar5 = piVar1;
    if (piVar5 != (int *)0x0) {
      piVar1 = (int *)*piVar5;
      if ((piVar5[4] & 0x40000U) != 0) {
        if (piVar1 != (int *)0x0) {
          piVar1[1] = piVar5[1];
        }
        if ((int *)piVar5[1] == (int *)0x0) {
          DAT_803defd4 = (int *)*piVar5;
        }
        else {
          *(int *)piVar5[1] = *piVar5;
        }
        piVar5[4] = piVar5[4] & 0xffff;
        if (piVar5[0xf] != 0xffffffff) {
          FUN_80272224(piVar5[0xf]);
        }
        goto LAB_80281724;
      }
      if ((piVar5[4] & 0x20001U) != 0) {
        FUN_80280824((int)piVar5,local_30,&local_40,&local_34,&local_38,&local_3c);
      }
      uVar2 = piVar5[4];
      if ((uVar2 & 0x80000) == 0) {
        if ((uVar2 & 0x20000) == 0) {
          uVar2 = FUN_80273090(piVar5[0xf]);
          piVar5[0xf] = uVar2;
          if (uVar2 == 0xffffffff) {
            uVar2 = piVar5[4];
            if ((uVar2 & 2) == 0) {
              piVar5[4] = uVar2 | 0x40000;
            }
            else {
              piVar5[4] = uVar2 | 0x20000;
            }
          }
        }
        else {
          dVar6 = (double)local_30[0];
          if ((dVar7 == dVar6) && ((uVar2 & 4) != 0)) {
            piVar5[4] = uVar2 | 0x80000;
            piVar5[4] = piVar5[4] & 0xfffdffff;
          }
          else {
            if ((dVar7 == dVar6) && ((uVar2 & 0x40) != 0)) {
              if (*piVar5 != 0) {
                *(int *)(*piVar5 + 4) = piVar5[1];
              }
              if ((int *)piVar5[1] == (int *)0x0) {
                DAT_803defd4 = (int *)*piVar5;
              }
              else {
                *(int *)piVar5[1] = *piVar5;
              }
              piVar5[4] = piVar5[4] & 0xffff;
              if (piVar5[0xf] != 0xffffffff) {
                FUN_80272224(piVar5[0xf]);
              }
              goto LAB_80281724;
            }
            if ((uVar2 & 1) == 0) {
              iVar3 = piVar5[2];
              if ((iVar3 == 0) || (*(char *)(iVar3 + 0x1c) != -1)) {
                if (iVar3 == 0) {
                  uVar4 = *(undefined *)((int)piVar5 + 0x46);
                }
                else {
                  uVar4 = *(undefined *)(iVar3 + 0x1c);
                }
                iVar3 = FUN_80271f14(*(undefined2 *)(piVar5 + 0x11),0x7f,0x40,uVar4,
                                     (uint)((uVar2 & 0x10) != 0));
                piVar5[0xf] = iVar3;
                if (iVar3 != -1) goto LAB_8028161c;
              }
              if ((piVar5[4] & 2U) != 0) goto LAB_80281724;
              piVar5[4] = piVar5[4] | 0x40000;
              piVar5[4] = piVar5[4] & 0xfffdffff;
            }
            else {
              iVar3 = FUN_8028103c(dVar6,(double)local_34,(double)local_38,(double)local_3c,
                                   (double)local_40,(int)piVar5);
              if (iVar3 != 0) goto LAB_80281724;
            }
          }
        }
LAB_8028161c:
        if (piVar5[0xf] != -1) {
          if ((piVar5[4] & 1U) != 0) {
            FUN_80280f28((double)local_30[0],(int)piVar5);
          }
          if ((dVar7 == (double)local_30[0]) && ((piVar5[4] & 4U) != 0)) {
            FUN_80272224(piVar5[0xf]);
            piVar5[0xf] = -1;
            uVar2 = piVar5[4];
            if ((uVar2 & 2) == 0) {
              piVar5[4] = uVar2 | 0x40000;
            }
            else {
              piVar5[4] = uVar2 | 0x80000;
            }
          }
          else {
            FUN_80280d08((double)local_30[0],(double)local_34,(double)local_38,(double)local_3c,
                         (double)local_40,(int)piVar5);
          }
        }
        if (((piVar5[4] & 0x100000U) != 0) &&
           (piVar5[0x13] = (int)(float)((double)(float)piVar5[0x13] + dVar8),
           dVar9 <= (double)(float)piVar5[0x13])) {
          piVar5[4] = piVar5[4] & 0xffefffff;
        }
        goto LAB_80281724;
      }
      iVar3 = piVar5[2];
      if (((iVar3 == 0) || ((iVar3 != 0 && (*(char *)(iVar3 + 0x1c) != -1)))) &&
         (dVar7 != (double)local_30[0])) {
        piVar5[4] = piVar5[4] & 0xfff7ffff;
        piVar5[4] = piVar5[4] | 0x20000;
      }
      goto LAB_80281724;
    }
    FUN_8028116c();
    FUN_8028026c();
    FUN_80280648();
  }
  else {
    DAT_803defd0 = DAT_803defd0 + -1;
  }
  return;
}

