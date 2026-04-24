// Function: FUN_80280c30
// Entry: 80280c30
// Size: 972 bytes

void FUN_80280c30(void)

{
  undefined uVar1;
  int **ppiVar2;
  int *piVar3;
  int iVar4;
  int *piVar5;
  int **ppiVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30 [3];
  
  if (DAT_803de350 == '\0') {
    DAT_803de36b = 0;
    dVar8 = (double)FLOAT_803e7880;
    DAT_803de350 = '\x03';
    dVar9 = (double)FLOAT_803e78c4;
    DAT_803de36c = 0;
    dVar10 = (double)FLOAT_803e78a4;
    DAT_803de36d = 0;
    ppiVar2 = DAT_803de354;
LAB_80280fc0:
    ppiVar6 = ppiVar2;
    if (ppiVar6 != (int **)0x0) {
      ppiVar2 = (int **)*ppiVar6;
      if (((uint)ppiVar6[4] & 0x40000) != 0) {
        if (ppiVar2 != (int **)0x0) {
          ppiVar2[1] = ppiVar6[1];
        }
        if ((int **)ppiVar6[1] == (int **)0x0) {
          DAT_803de354 = (int **)*ppiVar6;
        }
        else {
          *ppiVar6[1] = (int)*ppiVar6;
        }
        ppiVar6[4] = (int *)((uint)ppiVar6[4] & 0xffff);
        if (ppiVar6[0xf] != (int *)0xffffffff) {
          FUN_80271ac0();
        }
        goto LAB_80280fc0;
      }
      if (((uint)ppiVar6[4] & 0x20001) != 0) {
        FUN_802800c0(ppiVar6,local_30,&local_40,&local_34,&local_38,&local_3c);
      }
      piVar3 = ppiVar6[4];
      if (((uint)piVar3 & 0x80000) == 0) {
        if (((uint)piVar3 & 0x20000) == 0) {
          piVar3 = (int *)FUN_8027292c(ppiVar6[0xf]);
          ppiVar6[0xf] = piVar3;
          if (piVar3 == (int *)0xffffffff) {
            piVar3 = ppiVar6[4];
            if (((uint)piVar3 & 2) == 0) {
              ppiVar6[4] = (int *)((uint)piVar3 | 0x40000);
            }
            else {
              ppiVar6[4] = (int *)((uint)piVar3 | 0x20000);
            }
          }
        }
        else {
          dVar7 = (double)local_30[0];
          if ((dVar8 == dVar7) && (((uint)piVar3 & 4) != 0)) {
            ppiVar6[4] = (int *)((uint)piVar3 | 0x80000);
            ppiVar6[4] = (int *)((uint)ppiVar6[4] & 0xfffdffff);
          }
          else {
            if ((dVar8 == dVar7) && (((uint)piVar3 & 0x40) != 0)) {
              if (*ppiVar6 != (int *)0x0) {
                (*ppiVar6)[1] = (int)ppiVar6[1];
              }
              if ((int **)ppiVar6[1] == (int **)0x0) {
                DAT_803de354 = (int **)*ppiVar6;
              }
              else {
                *ppiVar6[1] = (int)*ppiVar6;
              }
              ppiVar6[4] = (int *)((uint)ppiVar6[4] & 0xffff);
              if (ppiVar6[0xf] != (int *)0xffffffff) {
                FUN_80271ac0();
              }
              goto LAB_80280fc0;
            }
            if (((uint)piVar3 & 1) == 0) {
              piVar5 = ppiVar6[2];
              if ((piVar5 == (int *)0x0) || (*(char *)(piVar5 + 7) != -1)) {
                if (piVar5 == (int *)0x0) {
                  uVar1 = *(undefined *)((int)ppiVar6 + 0x46);
                }
                else {
                  uVar1 = *(undefined *)(piVar5 + 7);
                }
                piVar3 = (int *)FUN_802717b0(*(undefined2 *)(ppiVar6 + 0x11),0x7f,0x40,uVar1,
                                             ((uint)piVar3 & 0x10) != 0);
                ppiVar6[0xf] = piVar3;
                if (piVar3 != (int *)0xffffffff) goto LAB_80280eb8;
              }
              if (((uint)ppiVar6[4] & 2) != 0) goto LAB_80280fc0;
              ppiVar6[4] = (int *)((uint)ppiVar6[4] | 0x40000);
              ppiVar6[4] = (int *)((uint)ppiVar6[4] & 0xfffdffff);
            }
            else {
              iVar4 = FUN_802808d8(dVar7,(double)local_34,(double)local_38,(double)local_3c,
                                   (double)local_40,ppiVar6);
              if (iVar4 != 0) goto LAB_80280fc0;
            }
          }
        }
LAB_80280eb8:
        if (ppiVar6[0xf] != (int *)0xffffffff) {
          if (((uint)ppiVar6[4] & 1) != 0) {
            FUN_802807c4((double)local_30[0],ppiVar6);
          }
          if ((dVar8 == (double)local_30[0]) && (((uint)ppiVar6[4] & 4) != 0)) {
            FUN_80271ac0(ppiVar6[0xf]);
            ppiVar6[0xf] = (int *)0xffffffff;
            piVar3 = ppiVar6[4];
            if (((uint)piVar3 & 2) == 0) {
              ppiVar6[4] = (int *)((uint)piVar3 | 0x40000);
            }
            else {
              ppiVar6[4] = (int *)((uint)piVar3 | 0x80000);
            }
          }
          else {
            FUN_802805a4((double)local_30[0],(double)local_34,(double)local_38,(double)local_3c,
                         (double)local_40,ppiVar6);
          }
        }
        if ((((uint)ppiVar6[4] & 0x100000) != 0) &&
           (ppiVar6[0x13] = (int *)(float)((double)(float)ppiVar6[0x13] + dVar9),
           dVar10 <= (double)(float)ppiVar6[0x13])) {
          ppiVar6[4] = (int *)((uint)ppiVar6[4] & 0xffefffff);
        }
        goto LAB_80280fc0;
      }
      piVar3 = ppiVar6[2];
      if (((piVar3 == (int *)0x0) || ((piVar3 != (int *)0x0 && (*(char *)(piVar3 + 7) != -1)))) &&
         (dVar8 != (double)local_30[0])) {
        ppiVar6[4] = (int *)((uint)ppiVar6[4] & 0xfff7ffff);
        ppiVar6[4] = (int *)((uint)ppiVar6[4] | 0x20000);
      }
      goto LAB_80280fc0;
    }
    FUN_80280a08();
    FUN_8027fb08();
    FUN_8027fee4();
  }
  else {
    DAT_803de350 = DAT_803de350 + -1;
  }
  return;
}

