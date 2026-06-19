/*
 * dfpulley - per-node spring/constraint integration step for the DF
 * (Dinosaur Forest) rope simulation. Sibling of dfbarrel
 * (DFRope_UpdateSimulation), which calls this once per solver tick.
 *
 * For each unlocked rope node it sums the spring forces from every
 * attached link (added when the node is the link's first endpoint,
 * subtracted otherwise), clamps the resulting force magnitude to the
 * rope's maxSlack, scales by stepPerTick, then advances the node's
 * velocity and position by the rope's step / inverseTicks factors
 * (semi-implicit Euler).
 */
#include "main/dll/DF/DFbarrel.h"
#include "dolphin/mtx.h"

extern f32 lbl_803E4DFC; /* 0.0f, dfbarrel TU */

void DFPulley_integrateLinks(DFRope* self)
{
    DFRopeNode* part;
    int j;
    int i;
    Vec accel;
    Vec velscaled;
    Vec scaled;
    f32 mag;
    f32 zero;

    part = self->nodes;
    i = 0;
    zero = lbl_803E4DFC;
    for (; i < self->count; i++, part++)
    {
        accel.z = zero;
        accel.y = zero;
        accel.x = zero;

        if (part->locked == 0)
        {
            for (j = 0; j < part->linkCount; j++)
            {
                DFRopeLink* link = part->links[j];
                if (part == link->a)
                {
                    PSVECAdd(&accel, (Vec*)link->force, &accel);
                }
                else
                {
                    PSVECSubtract(&accel, (Vec*)link->force, &accel);
                }
            }
            mag = PSVECMag(&accel);
            if (mag > self->maxSlack)
            {
                PSVECScale(&accel, &accel, self->maxSlack / mag);
            }
            PSVECScale(&accel, &accel, self->stepPerTick);
            PSVECAdd(&accel, (Vec*)part->force, &accel);
            PSVECAdd((Vec*)part->velocity, &accel, (Vec*)part->velocity);
            PSVECScale((Vec*)part->velocity, &velscaled, self->damping);
            PSVECSubtract((Vec*)part->velocity, &velscaled, (Vec*)part->velocity);
            part->velocity[1] = self->step * self->inverseTicks
                + part->velocity[1];
            PSVECScale((Vec*)part->velocity, &scaled, self->step);
            PSVECAdd((Vec*)part->pos, &scaled, (Vec*)part->pos);
        }
    }
}
