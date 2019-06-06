package com.cv.secureapp.core;

import java.io.Serializable;

public class Triplet<T1, T2, T3> {

    private final T1 $1;
    private final T2 $2;
    private final T3 $3;

    private Triplet(T1 first, T2 second, T3 third){
        this.$1 = first;
        this.$2 = second;
        this.$3 = third;
    }

    public T1 $1() {
        return $1;
    }

    public T2 $2() {
        return $2;
    }

    public T3 $3() {
        return $3;
    }

    public static <T1, T2, T3>Triplet<T1, T2, T3> with(T1 first, T2 second, T3 third){
        return new Triplet<T1, T2, T3>(first,second,third);
    }

    @Override
    public String toString() {
        return "Triplet{" +
                "$1=" + $1 +
                ", $2=" + $2 +
                ", $3=" + $3 +
                '}';
    }

}
