// Function: FUN_80043ce8
// Entry: 80043ce8
// Size: 1708 bytes

undefined4 FUN_80043ce8(uint *param_1,int param_2,int param_3)

{
  bool bVar1;
  bool bVar2;
  uint *puVar3;
  uint *puVar4;
  uint *puVar5;
  uint *puVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  uint *puVar10;
  
  iVar7 = 0;
  bVar1 = false;
  bVar2 = false;
  iVar8 = 0;
  puVar10 = (uint *)(&DAT_8035f3e8)[param_2];
  if (((puVar10 == (uint *)0x0) || ((&DAT_8035f3e8)[param_3] == 0)) &&
     (bVar1 = puVar10 == (uint *)0x0, (&DAT_8035f3e8)[param_3] == 0)) {
    bVar2 = true;
  }
  puVar6 = (uint *)(&DAT_8035f3e8)[param_3];
  if (param_1 == (uint *)&DAT_8035cef0) {
    iVar8 = 0x800;
  }
  else if (param_1 == (uint *)&DAT_8035a010) {
    iVar8 = 3000;
  }
  else if (param_1 == (uint *)&DAT_80356010) {
    iVar8 = 0x1000;
  }
  else if (param_1 == (uint *)&DAT_80352010) {
    iVar8 = 0x1000;
  }
  else if (param_1 == (uint *)&DAT_80350010) {
    iVar8 = 0x800;
  }
  else if (param_1 == (uint *)&DAT_8034e010) {
    iVar8 = 0x800;
  }
  else if (param_1 == (uint *)&DAT_803460d0) {
    iVar8 = 0x1fd0;
  }
  puVar3 = param_1;
  if ((param_1 == (uint *)&DAT_80356010) || (param_1 == (uint *)&DAT_80352010)) {
    for (; iVar8 != 0; iVar8 = iVar8 + -1) {
      if ((!bVar1) && (*puVar10 == 0xffffffff)) {
        bVar1 = true;
      }
      if ((!bVar2) && (*puVar6 == 0xffffffff)) {
        bVar2 = true;
      }
      if (((bVar1) || (uVar9 = *puVar10, uVar9 == 0xffffffff)) || ((uVar9 & 0x80000000) == 0)) {
        if (((bVar2) || (uVar9 = *puVar6, uVar9 == 0xffffffff)) || ((uVar9 & 0x80000000) == 0)) {
          if ((bVar1) || (*puVar10 == 0)) {
            if ((bVar2) || (*puVar6 == 0)) {
              *puVar3 = 0;
            }
            else {
              *puVar3 = *puVar6;
            }
          }
          else {
            *puVar3 = *puVar10;
          }
        }
        else {
          *puVar3 = uVar9;
        }
      }
      else {
        *puVar3 = uVar9 & 0x7fffffff;
        *puVar3 = *puVar3 | 0x40000000;
      }
      puVar10 = puVar10 + 1;
      puVar6 = puVar6 + 1;
      iVar7 = iVar7 + 1;
      puVar3 = puVar3 + 1;
    }
  }
  else {
    puVar3 = puVar10;
    puVar4 = puVar6;
    puVar5 = param_1;
    if (param_1 == (uint *)&DAT_80350010) {
      for (; iVar8 != 0; iVar8 = iVar8 + -1) {
        if (((bVar1) || (uVar9 = *puVar3, uVar9 == 0xffffffff)) || ((uVar9 & 0x10000000) == 0)) {
          if (((bVar2) || (uVar9 = *puVar4, uVar9 == 0xffffffff)) || ((uVar9 & 0x10000000) == 0)) {
            if ((bVar1) || (*puVar3 != 0xffffffff)) {
              if ((bVar2) || (*puVar4 != 0xffffffff)) {
                if ((bVar1) || (*puVar3 == 0)) {
                  if ((bVar2) || (*puVar4 == 0)) {
                    *puVar5 = 0;
                  }
                  else {
                    *puVar5 = *puVar4;
                  }
                }
                else {
                  *puVar5 = *puVar3;
                }
              }
              else {
                *puVar5 = 0;
                bVar2 = true;
              }
            }
            else {
              *puVar5 = 0;
              bVar1 = true;
            }
          }
          else {
            *puVar5 = uVar9 & 0xffffff | 0x20000000;
            if ((puVar10 != (uint *)0x0) && (*puVar3 == 0xffffffff)) {
              bVar1 = true;
            }
          }
        }
        else {
          *puVar5 = uVar9;
          if ((puVar6 != (uint *)0x0) && (*puVar4 == 0xffffffff)) {
            bVar2 = true;
          }
        }
        iVar7 = iVar7 + 1;
        puVar3 = puVar3 + 1;
        puVar4 = puVar4 + 1;
        puVar5 = puVar5 + 1;
      }
    }
    else {
      puVar3 = param_1;
      if (param_1 == (uint *)&DAT_8034e010) {
        for (; iVar8 != 0; iVar8 = iVar8 + -1) {
          if ((bVar1) || (*puVar10 != 0xffffffff)) {
            if ((bVar2) || (*puVar6 != 0xffffffff)) {
              if (((bVar1) || (uVar9 = *puVar10, uVar9 == 0xffffffff)) ||
                 ((uVar9 & 0x80000000) == 0)) {
                if (((bVar2) || (uVar9 = *puVar6, uVar9 == 0xffffffff)) ||
                   ((uVar9 & 0x80000000) == 0)) {
                  if ((bVar1) || (*puVar10 == 0)) {
                    if ((bVar2) || (*puVar6 == 0)) {
                      *puVar3 = 0;
                    }
                    else {
                      *puVar3 = *puVar6;
                    }
                  }
                  else {
                    *puVar3 = *puVar10;
                  }
                }
                else {
                  *puVar3 = uVar9 & 0x7fffffff | 0x20000000;
                }
              }
              else {
                *puVar3 = uVar9;
              }
            }
            else {
              *puVar3 = 0;
              bVar2 = true;
            }
          }
          else {
            *puVar3 = 0;
            bVar1 = true;
          }
          puVar10 = puVar10 + 1;
          puVar6 = puVar6 + 1;
          iVar7 = iVar7 + 1;
          puVar3 = puVar3 + 1;
        }
      }
      else {
        puVar3 = puVar10;
        if (param_1 == (uint *)&DAT_803460d0) {
          for (; iVar8 != 0; iVar8 = iVar8 + -1) {
            if ((bVar1) || (*puVar10 != 0xffffffff)) {
              if ((bVar2) || (*puVar6 != 0xffffffff)) {
                if (((bVar1) || (uVar9 = *puVar10, uVar9 == 0xffffffff)) ||
                   ((uVar9 & 0x80000000) == 0)) {
                  if (((bVar2) || (uVar9 = *puVar6, uVar9 == 0xffffffff)) ||
                     ((uVar9 & 0x80000000) == 0)) {
                    if ((bVar1) || (*puVar10 == 0)) {
                      if ((bVar2) || (*puVar6 == 0)) {
                        *puVar5 = 0;
                      }
                      else {
                        *puVar5 = *puVar6;
                      }
                    }
                    else {
                      *puVar5 = *puVar10;
                    }
                  }
                  else {
                    *puVar5 = uVar9 & 0x7fffffff | 0x20000000;
                  }
                }
                else {
                  *puVar5 = uVar9;
                }
              }
              else {
                *puVar5 = 0;
                bVar2 = true;
              }
            }
            else {
              *puVar5 = 0;
              bVar1 = true;
            }
            puVar10 = puVar10 + 1;
            puVar6 = puVar6 + 1;
            iVar7 = iVar7 + 1;
            puVar5 = puVar5 + 1;
          }
        }
        else {
          for (; iVar8 != 0; iVar8 = iVar8 + -1) {
            if ((!bVar1) && (*puVar3 == 0xffffffff)) {
              bVar1 = true;
            }
            if ((!bVar2) && (*puVar4 == 0xffffffff)) {
              bVar2 = true;
            }
            if (((bVar1) || (uVar9 = *puVar3, uVar9 == 0xffffffff)) || ((uVar9 & 0x10000000) == 0))
            {
              if (((bVar2) || (uVar9 = *puVar4, uVar9 == 0xffffffff)) || ((uVar9 & 0x10000000) == 0)
                 ) {
                if ((bVar1) || (puVar10 == (uint *)0x0)) {
                  if ((bVar2) || (puVar6 == (uint *)0x0)) {
                    *puVar5 = 0;
                  }
                  else {
                    *puVar5 = *puVar4;
                  }
                }
                else {
                  *puVar5 = *puVar3;
                }
              }
              else {
                *puVar5 = uVar9 & 0xffffff | 0x20000000;
              }
            }
            else {
              *puVar5 = uVar9;
            }
            iVar7 = iVar7 + 1;
            puVar3 = puVar3 + 1;
            puVar4 = puVar4 + 1;
            puVar5 = puVar5 + 1;
          }
        }
      }
    }
  }
  param_1[iVar7 + -1] = 0xffffffff;
  return 1;
}

