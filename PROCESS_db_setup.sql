
use syslog;
INSERT INTO classes (id, class) VALUES (10004, "PROCESS");
INSERT INTO fields (field, field_type, pattern_type) VALUES ("scanID", "int", "NUMBER");
INSERT INTO fields (field, field_type, pattern_type) VALUES ("processID", "int", "NUMBER");
INSERT INTO fields (field, field_type, pattern_type) VALUES ("creationDate", "int", "NUMBER");
INSERT INTO fields (field, field_type, pattern_type) VALUES ("terminationDate", "int", "NUMBER");
INSERT INTO fields (field, field_type, pattern_type) VALUES ("parentProcessID", "int", "NUMBER");
INSERT INTO fields (field, field_type, pattern_type) VALUES ("processName", "string", "QSTRING");
INSERT INTO fields (field, field_type, pattern_type) VALUES ("OSName", "string", "QSTRING");
INSERT INTO fields (field, field_type, pattern_type) VALUES ("handle", "string", "QSTRING");
INSERT INTO fields (field, field_type, pattern_type) VALUES ("OSCreationClassName", "string", "QSTRING");
INSERT INTO fields (field, field_type, pattern_type) VALUES ("parentProcessName", "string", "QSTRING");


INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="PROCESS"), (SELECT id FROM fields WHERE field="scanID"), 5);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="PROCESS"), (SELECT id FROM fields WHERE field="processID"), 6);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="PROCESS"), (SELECT id FROM fields WHERE field="creationDate"), 7);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="PROCESS"), (SELECT id FROM fields WHERE field="terminationDate"), 8);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="PROCESS"), (SELECT id FROM fields WHERE field="parentProcessID"), 9);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="PROCESS"), (SELECT id FROM fields WHERE field="processName"), 11);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="PROCESS"), (SELECT id FROM fields WHERE field="OSName"), 12);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="PROCESS"), (SELECT id FROM fields WHERE field="handle"), 13);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="PROCESS"), (SELECT id FROM fields WHERE field="OSCreationClassName"), 14);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="PROCESS"), (SELECT id FROM fields WHERE field="parentProcessName"), 15);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="PROCESS"), (SELECT id FROM fields WHERE field="cve"), 16);
