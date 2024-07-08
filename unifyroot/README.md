# UnifyRoot

UnifyRoot is a powerful static analysis designed to reconstruct a full Linux filesystem from a corpus of extracted partitions. UnifyRoot identifies which partition should be the root filesystem,
what unresolved references exist, and how mounting other filesystems can resolve these references. The resulting **partition map** is provided to a user and then used to generate a **unified filesystem archive**.

### The Problem We Solve

In the world of embedded systems, it's common to encounter multiple filesystem images extracted from a single device. These images often represent different partitions or overlays that, when combined, form the complete filesystem of the device. However, piecing these fragments together manually can be a time-consuming and error-prone process.

UnifyRoot automates this reconstruction, intelligently combining multiple filesystem images into a single, coherent structure. By doing so, it provides a clear view of the entire filesystem, making it easier to analyze, understand, and work with embedded system software.

### Key Features

- **Intelligent Mount Point Detection**: Automatically determines the optimal mounting points for each filesystem image.
- **Reference Resolution**: Identifies and resolves file references across different filesystem images.
- **Flexible Input Handling**: Works with multiple tar.gz archives, making it compatible with most filesystem extraction tools.
- **Optimized Unification**: Employs advanced algorithms to maximize resolved references while minimizing unnecessary mounts.
- **Preservation of Filesystem Integrity**: Ensures that the unified structure maintains the integrity and hierarchy of each individual filesystem.
