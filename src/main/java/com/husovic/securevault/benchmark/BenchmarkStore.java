package com.husovic.securevault.benchmark;

import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/** Akumulira sve izmjerene redove tokom rada aplikacije radi kasnijeg izvoza. */
@Component
public class BenchmarkStore {

    private final CopyOnWriteArrayList<BenchmarkRow> rows = new CopyOnWriteArrayList<>();

    public void addAll(List<BenchmarkRow> newRows) {
        rows.addAll(newRows);
    }

    public List<BenchmarkRow> all() {
        return List.copyOf(rows);
    }

    public int clear() {
        int n = rows.size();
        rows.clear();
        return n;
    }
}
