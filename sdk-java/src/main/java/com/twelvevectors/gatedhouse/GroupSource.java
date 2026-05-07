package com.twelvevectors.gatedhouse;

/**
 * Pluggable extension point for where group data originates. Configured at
 * factory time via {@link GatedhouseConfig.Builder#groupSource}.
 *
 * <p>Both built-in and custom implementations write to the same local
 * {@code gatedhouse.groups} / {@code gatedhouse.group_memberships} tables —
 * the difference is who triggers those writes.
 *
 * <ul>
 *   <li>{@link LocalGroupSource}: the host calls {@code gh.groupManager()}
 *       methods directly. {@link #start} is a no-op.</li>
 *   <li>Custom (e.g., a Citadel bridge): on {@link #start}, register a
 *       listener with the host's transport that translates incoming events
 *       into {@code gh.groupManager()} write calls. Release the listener on
 *       {@link #close}.</li>
 * </ul>
 *
 * <p>Implementations must be safe for concurrent invocation by multiple
 * threads — Gatedhouse itself is intended to be shared across a process.
 */
public interface GroupSource extends AutoCloseable {

    /**
     * Called once by {@link GatedhouseFactory#create(GatedhouseConfig)} after
     * the schema check passes and the {@link Gatedhouse} instance is fully
     * constructed. Implementations typically capture the reference and use
     * it inside event handlers to call {@code gatedhouse.groupManager()}.
     */
    void start(Gatedhouse gatedhouse);

    /**
     * Called when the {@link Gatedhouse} instance is closed. Implementations
     * should release listeners and any other resources they hold. Must be
     * idempotent.
     */
    @Override
    void close();
}
