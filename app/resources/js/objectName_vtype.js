Ext.require('Ext.form.field.VTypes', function() {
	var timeTest = /^[0-9a-zA-Z]{1}([0-9a-zA-Z_-]|[ ]|[.])*$/;
	var timeTest2 = /^[a-zA-Z]{1}[0-9a-zA-Z._-]*$/;
	var timeTest3 = /^[0-9a-zA-Z]{1}([0-9a-zA-Z_-]|[ ]|[.]|[/])*$/;
	var timeTest4 = /^([0-9]{1}([0-9]|[-]|[,])*)$/;
	var timeTest5 = /^[0-9a-zA-Z]{1}([0-9a-zA-Z_-]|[ ]|[.]|[/]|[:])*$/;
    Ext.apply(Ext.form.field.VTypes, {
        objectName: function(val, field) {
        	return timeTest.test(val);
    	},
    	objectNameText: "A valid object name must start with an alphanumeric character and can contain zero or more alphanumeric characters, underscore '_', hyphen '-', dot '.' or spaces"
    });
	Ext.apply(Ext.form.field.VTypes, {
       	 	objectName2: function(val, field) {
                return timeTest2.test(val);
        },
        objectName2Text: "alphanumeric string begin with letter: [0-9a-zA-Z._-]"
    });
	Ext.apply(Ext.form.field.VTypes, {
        objectName3: function(val, field) {
        	return timeTest3.test(val);
    	},
    	objectName3Text: "A valid object name must start with an alphanumeric character and can contain zero or more alphanumeric characters, underscore '_', hyphen '-', dot '.', '/' or spaces"
    });
	Ext.apply(Ext.form.field.VTypes, {
        objectName4: function(val, field) {
        	return timeTest4.test(val);
    	},
    	objectName4Text: "Port can be a single port #, range (1-65535), or comma separated (80, 8080, 443)"
    });
	Ext.apply(Ext.form.field.VTypes, {
        objectName5: function(val, field) {
        	return timeTest5.test(val);
    	},
    	objectName5Text: "A valid object name must start with an alphanumeric character and can contain zero or more alphanumeric characters, underscore '_', hyphen '-', dot '.', '/', ':' or spaces"
    });
});
