package com.example.demo.security;

import com.google.common.collect.ImmutableSet;

import java.util.Set;

public enum ApplicationUserRole {
    STUDENT(ImmutableSet.of()),
    ADMIN(ImmutableSet.of(
            ApplicationUserPermission.COURSE_READ,
            ApplicationUserPermission.COURSE_WRITE,
            ApplicationUserPermission.STUDENT_READ,
            ApplicationUserPermission.STUDENT_WRITE));

    private final Set<ApplicationUserPermission> permissions;

    ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
        this.permissions = permissions;
    }

    public Set<ApplicationUserPermission> getPermissions() {
        return permissions;
    }
}
