// Function: FUN_80111fb0
// Entry: 80111fb0
// Size: 308 bytes

undefined4 FUN_80111fb0(int param_1)

{
  short sVar1;
  
  sVar1 = *(short *)(param_1 + 0x46);
  if (sVar1 != 0x2ca) {
    if (sVar1 < 0x2ca) {
      if (sVar1 < 0x24e) {
        if (sVar1 != 0x170) {
          if (sVar1 < 0x170) {
            if (sVar1 != 0x16d) {
              if (0x16c < sVar1) {
                return 0;
              }
              if (sVar1 != 0x155) {
                return 0;
              }
            }
          }
          else if (sVar1 != 0x200) {
            if (sVar1 < 0x200) {
              if (sVar1 != 0x1da) {
                return 0;
              }
            }
            else if (sVar1 < 0x24c) {
              return 0;
            }
          }
        }
      }
      else if (sVar1 != 0x292) {
        if (sVar1 < 0x292) {
          if ((sVar1 != 0x28d) && (((0x28c < sVar1 || (0x27c < sVar1)) || (sVar1 < 0x27b)))) {
            return 0;
          }
        }
        else if (sVar1 != 0x2b9) {
          if (0x2b8 < sVar1) {
            return 0;
          }
          if (sVar1 != 0x2ab) {
            return 0;
          }
        }
      }
    }
    else if (sVar1 != 0x4ad) {
      if (sVar1 < 0x4ad) {
        if (sVar1 != 0x360) {
          if (sVar1 < 0x360) {
            if (sVar1 != 0x337) {
              if (0x336 < sVar1) {
                return 0;
              }
              if (sVar1 != 0x306) {
                return 0;
              }
            }
          }
          else if (sVar1 != 0x3fd) {
            if (0x3fc < sVar1) {
              return 0;
            }
            if (0x38a < sVar1) {
              return 0;
            }
            if (sVar1 < 0x389) {
              return 0;
            }
          }
        }
      }
      else if (sVar1 != 0x4fc) {
        if (sVar1 < 0x4fc) {
          if (sVar1 != 0x4d3) {
            if (0x4d2 < sVar1) {
              return 0;
            }
            if (sVar1 != 0x4b9) {
              return 0;
            }
          }
        }
        else if (sVar1 != 0x506) {
          return 0;
        }
      }
    }
  }
  return 1;
}

