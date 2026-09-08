# Intersection result lifecycle

`trackGetIntersect` now expresses its result initialization as a native loop over
`TrackHitResults`. The previous source hand-expanded eight iterations and then
implemented a separate remainder loop, including an unreachable `count > 8`
branch after clamping the count to four. GC/1.3 generates that exact unrolled
instruction sequence from the simple loop under this TU's unchanged settings.
The expansion belongs to the compiler, not the reconstructed C source.

The same record now supplies the postprocessing object and plane accesses,
replacing raw pointer-table offsets. The public storage parameter remains
`void*` for existing caller overlays; one typed local establishes this wrapper's
record view. `TRACK_HIT_MAX_POINTS` names the evidenced four-point capacity and
sizes the record's parallel arrays. All layout assertions live beside the
canonical definition in `track_hit_results.h`.

For each requested point, capped at four, the wrapper installs plane
`(0, 1, 0, 0)` and a null contact object. It resets `hitCount` without clearing
input radii or query types. The coordinator fills the results and returns a
mask. Object-backed normals are then transformed in place and contacts are
registered when a contact-source object was supplied. The byte mask is stored
and returned; it is distinct from the coordinator's `hitCount` field. Naming
the local `hitMask` removes that ambiguity. The existing flags argument is
unused, and nonpositive counts are forwarded unchanged.

## Validation

- The 556-byte wrapper remains 100% exact: all 139 retail instructions match.
  Every compiled function body, allocated section, named symbol layout and
  resolved relocation destination in the TU is unchanged. Anonymous literal
  symbols can renumber when the expanded source is removed.
- `python3 tools/test_track_intersect_wrapper.py` executes the production
  wrapper against controlled engine callbacks: 96 scenarios each at O0/O2.
  It checks the upper count clamp, forwarding of nonpositive counts, preserved
  query inputs and unused slots, initial planes, object-normal conversion,
  contact registration, hit-count ownership and byte-mask conversion. Changing
  the initial up-normal to zero fails the oracle.
- The host harness models pointer-bearing records with native pointers and
  mocks geometry and transforms. It does not establish that the inner geometry
  coordinator accepts nonpositive counts. Retail layouts are checked by MWCC
  assertions, and generated code is checked separately against retail.
- The complete objdiff unit report is unchanged, and all 1,001 other source
  objects retain their raw hashes. The only raw object difference is anonymous
  relocation-symbol renumbering in `track_dolphin.o`.
- `python3 configure.py --matching`, `ninja all_source` and the strict retail
  checksum pass, with each Ninja invocation limited to 30 seconds. The TU remains
  `NonMatching`; the checksum verifies integration with its retail object, while
  the separate object audit verifies the reconstructed source.
