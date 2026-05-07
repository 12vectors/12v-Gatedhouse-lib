package com.twelvevectors.gatedhouse;

public enum EntityType {

    USER("user"),
    AGENT("agent");

    private final String dbValue;

    EntityType(String dbValue) {
        this.dbValue = dbValue;
    }

    public String dbValue() {
        return dbValue;
    }

    public static EntityType fromDbValue(String value) {
        for (EntityType t : values()) {
            if (t.dbValue.equals(value)) {
                return t;
            }
        }
        throw new IllegalArgumentException("Unknown entity_type value: " + value);
    }
}
