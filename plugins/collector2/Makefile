
#Don't forget to add your plugin to config.panda!

# If you need custom CFLAGS or LIBS, set them up here
CFLAGS+= -Wno-error -std=c++17 -Ofast # -fsanitize=address -g -Wno-unused-variable -Wno-unused-result -Wno-write-strings
LIBS+=-lhdf5_serial_hl
#
# Example: this plugin has runtime symbol dependencies on plugin_x:
# # LIBS+=-L$(PLUGIN_TARGET_DIR) -l:panda_plugin_x.so
# # Also create a plugin_plugin.d file in this directory to ensure plugin_x
# # gets compiled before this plugin, example contents:
# # plugin-this_plugins_name : plugin-plugin_x
# # or if you're using the extra plugins dir:
# # extra-plugin-this_plugins_name : extra-plugin-plugin_x
#
# # The main rule for your plugin. List all object-file dependencies.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: \
 	$(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o $(PLUGIN_OBJ_DIR)/utils.o