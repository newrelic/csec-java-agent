package com.newrelic.agent.security.intcodeagent.filelogging;

import org.crac.CheckpointException;
import org.crac.Context;
import org.crac.Resource;
import org.crac.RestoreException;

import java.io.Closeable;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Phaser;

class CracResource implements Resource, Runnable {
    private final Phaser phaser = new Phaser(2);
    private final List<Closeable> toClose = new ArrayList<>();
    private final List<Runnable> toReopen = new ArrayList<>();

    public synchronized void addAction(Closeable close, Runnable reopen) {
        toClose.add(close);
        toReopen.add(reopen);
    }

    public void beforeCheckpoint(Context<? extends Resource> ctx) throws CheckpointException {
        FileLoggerThreadPool threadPool = FileLoggerThreadPool.getInstance();
        assert !threadPool.isLoggingToStdOut;
        threadPool.getExecutor().submit(this);
        if (phaser.arriveAndAwaitAdvance() < 0) {
            throw new CheckpointException("Failed to close the writer");
        }
    }

    public void afterRestore(Context<? extends Resource> ctx) throws RestoreException {
        if (phaser.arriveAndAwaitAdvance() < 0) {
            throw new RestoreException("Cannot restore writer");
        }
    }

    @Override
    public synchronized void run() {
        try {
            for (Closeable c : toClose) {
                c.close();
            }
            phaser.arriveAndAwaitAdvance();
            // checkpoint/restore happens here
            phaser.arriveAndAwaitAdvance();
            for (Runnable r : toReopen) {
                r.run();
            }
        } catch (Exception e) {
            phaser.forceTermination();
        }
    }
}
