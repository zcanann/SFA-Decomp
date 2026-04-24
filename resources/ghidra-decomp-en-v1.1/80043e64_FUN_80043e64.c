// Function: FUN_80043e64
// Entry: 80043e64
// Size: 1708 bytes

undefined4 FUN_80043e64(uint *param_1,int param_2,int param_3)

{
  bool bVar1;
  bool bVar2;
  uint *puVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  uint *puVar7;
  uint *puVar8;
  uint *puVar9;
  uint *puVar10;
  
  iVar4 = 0;
  bVar1 = false;
  bVar2 = false;
  iVar5 = 0;
  puVar8 = (uint *)(&DAT_80360048)[param_2];
  if (((puVar8 == (uint *)0x0) || ((&DAT_80360048)[param_3] == 0)) &&
     (bVar1 = puVar8 == (uint *)0x0, (&DAT_80360048)[param_3] == 0)) {
    bVar2 = true;
  }
  puVar3 = (uint *)(&DAT_80360048)[param_3];
  if (param_1 == (uint *)&DAT_8035db50) {
    iVar5 = 0x800;
  }
  else if (param_1 == (uint *)&DAT_8035ac70) {
    iVar5 = 3000;
  }
  else if (param_1 == (uint *)&DAT_80356c70) {
    iVar5 = 0x1000;
  }
  else if (param_1 == (uint *)&DAT_80352c70) {
    iVar5 = 0x1000;
  }
  else if (param_1 == (uint *)&DAT_80350c70) {
    iVar5 = 0x800;
  }
  else if (param_1 == (uint *)&DAT_8034ec70) {
    iVar5 = 0x800;
  }
  else if (param_1 == (uint *)&DAT_80346d30) {
    iVar5 = 0x1fd0;
  }
  puVar9 = param_1;
  if ((param_1 == (uint *)&DAT_80356c70) || (param_1 == (uint *)&DAT_80352c70)) {
    for (; iVar5 != 0; iVar5 = iVar5 + -1) {
      if ((!bVar1) && (*puVar8 == 0xffffffff)) {
        bVar1 = true;
      }
      if ((!bVar2) && (*puVar3 == 0xffffffff)) {
        bVar2 = true;
      }
      if (((bVar1) || (uVar6 = *puVar8, uVar6 == 0xffffffff)) || ((uVar6 & 0x80000000) == 0)) {
        if (((bVar2) || (uVar6 = *puVar3, uVar6 == 0xffffffff)) || ((uVar6 & 0x80000000) == 0)) {
          if ((bVar1) || (*puVar8 == 0)) {
            if ((bVar2) || (*puVar3 == 0)) {
              *puVar9 = 0;
            }
            else {
              *puVar9 = *puVar3;
            }
          }
          else {
            *puVar9 = *puVar8;
          }
        }
        else {
          *puVar9 = uVar6;
        }
      }
      else {
        *puVar9 = uVar6 & 0x7fffffff;
        *puVar9 = *puVar9 | 0x40000000;
      }
      puVar8 = puVar8 + 1;
      puVar3 = puVar3 + 1;
      iVar4 = iVar4 + 1;
      puVar9 = puVar9 + 1;
    }
  }
  else if (param_1 == (uint *)&DAT_80350c70) {
    puVar9 = (uint *)&DAT_80350c70;
    puVar7 = puVar8;
    puVar10 = puVar3;
    for (; iVar5 != 0; iVar5 = iVar5 + -1) {
      if (((bVar1) || (uVar6 = *puVar7, uVar6 == 0xffffffff)) || ((uVar6 & 0x10000000) == 0)) {
        if (((bVar2) || (uVar6 = *puVar10, uVar6 == 0xffffffff)) || ((uVar6 & 0x10000000) == 0)) {
          if ((bVar1) || (*puVar7 != 0xffffffff)) {
            if ((bVar2) || (*puVar10 != 0xffffffff)) {
              if ((bVar1) || (*puVar7 == 0)) {
                if ((bVar2) || (*puVar10 == 0)) {
                  *puVar9 = 0;
                }
                else {
                  *puVar9 = *puVar10;
                }
              }
              else {
                *puVar9 = *puVar7;
              }
            }
            else {
              *puVar9 = 0;
              bVar2 = true;
            }
          }
          else {
            *puVar9 = 0;
            bVar1 = true;
          }
        }
        else {
          *puVar9 = uVar6 & 0xffffff | 0x20000000;
          if ((puVar8 != (uint *)0x0) && (*puVar7 == 0xffffffff)) {
            bVar1 = true;
          }
        }
      }
      else {
        *puVar9 = uVar6;
        if ((puVar3 != (uint *)0x0) && (*puVar10 == 0xffffffff)) {
          bVar2 = true;
        }
      }
      puVar7 = puVar7 + 1;
      puVar9 = puVar9 + 1;
      puVar10 = puVar10 + 1;
      iVar4 = iVar4 + 1;
    }
  }
  else if (param_1 == (uint *)&DAT_8034ec70) {
    puVar9 = (uint *)&DAT_8034ec70;
    for (; iVar5 != 0; iVar5 = iVar5 + -1) {
      if ((bVar1) || (*puVar8 != 0xffffffff)) {
        if ((bVar2) || (*puVar3 != 0xffffffff)) {
          if (((bVar1) || (uVar6 = *puVar8, uVar6 == 0xffffffff)) || ((uVar6 & 0x80000000) == 0)) {
            if (((bVar2) || (uVar6 = *puVar3, uVar6 == 0xffffffff)) || ((uVar6 & 0x80000000) == 0))
            {
              if ((bVar1) || (*puVar8 == 0)) {
                if ((bVar2) || (*puVar3 == 0)) {
                  *puVar9 = 0;
                }
                else {
                  *puVar9 = *puVar3;
                }
              }
              else {
                *puVar9 = *puVar8;
              }
            }
            else {
              *puVar9 = uVar6 & 0x7fffffff | 0x20000000;
            }
          }
          else {
            *puVar9 = uVar6;
          }
        }
        else {
          *puVar9 = 0;
          bVar2 = true;
        }
      }
      else {
        *puVar9 = 0;
        bVar1 = true;
      }
      puVar8 = puVar8 + 1;
      puVar9 = puVar9 + 1;
      puVar3 = puVar3 + 1;
      iVar4 = iVar4 + 1;
    }
  }
  else {
    puVar9 = puVar8;
    puVar7 = puVar3;
    puVar10 = param_1;
    if (param_1 == (uint *)&DAT_80346d30) {
      puVar9 = (uint *)&DAT_80346d30;
      for (; iVar5 != 0; iVar5 = iVar5 + -1) {
        if ((bVar1) || (*puVar8 != 0xffffffff)) {
          if ((bVar2) || (*puVar3 != 0xffffffff)) {
            if (((bVar1) || (uVar6 = *puVar8, uVar6 == 0xffffffff)) || ((uVar6 & 0x80000000) == 0))
            {
              if (((bVar2) || (uVar6 = *puVar3, uVar6 == 0xffffffff)) || ((uVar6 & 0x80000000) == 0)
                 ) {
                if ((bVar1) || (*puVar8 == 0)) {
                  if ((bVar2) || (*puVar3 == 0)) {
                    *puVar9 = 0;
                  }
                  else {
                    *puVar9 = *puVar3;
                  }
                }
                else {
                  *puVar9 = *puVar8;
                }
              }
              else {
                *puVar9 = uVar6 & 0x7fffffff | 0x20000000;
              }
            }
            else {
              *puVar9 = uVar6;
            }
          }
          else {
            *puVar9 = 0;
            bVar2 = true;
          }
        }
        else {
          *puVar9 = 0;
          bVar1 = true;
        }
        puVar8 = puVar8 + 1;
        puVar9 = puVar9 + 1;
        puVar3 = puVar3 + 1;
        iVar4 = iVar4 + 1;
      }
    }
    else {
      for (; iVar5 != 0; iVar5 = iVar5 + -1) {
        if ((!bVar1) && (*puVar9 == 0xffffffff)) {
          bVar1 = true;
        }
        if ((!bVar2) && (*puVar7 == 0xffffffff)) {
          bVar2 = true;
        }
        if (((bVar1) || (uVar6 = *puVar9, uVar6 == 0xffffffff)) || ((uVar6 & 0x10000000) == 0)) {
          if (((bVar2) || (uVar6 = *puVar7, uVar6 == 0xffffffff)) || ((uVar6 & 0x10000000) == 0)) {
            if ((bVar1) || (puVar8 == (uint *)0x0)) {
              if ((bVar2) || (puVar3 == (uint *)0x0)) {
                *puVar10 = 0;
              }
              else {
                *puVar10 = *puVar7;
              }
            }
            else {
              *puVar10 = *puVar9;
            }
          }
          else {
            *puVar10 = uVar6 & 0xffffff | 0x20000000;
          }
        }
        else {
          *puVar10 = uVar6;
        }
        iVar4 = iVar4 + 1;
        puVar9 = puVar9 + 1;
        puVar7 = puVar7 + 1;
        puVar10 = puVar10 + 1;
      }
    }
  }
  param_1[iVar4 + -1] = 0xffffffff;
  return 1;
}

