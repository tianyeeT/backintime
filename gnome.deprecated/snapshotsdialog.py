#    Back In Time
#    Copyright (C) 2008-2009 Oprea Dan, Bart de Koning, Richard Bailey
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


import os
import os.path
import sys
import pygtk
pygtk.require("2.0")
import gtk
import gnomevfs
import gobject
import datetime
import gettext

import config
import tools
import messagebox
import gnometools
import restoredialog


_=gettext.gettext

class SnapshotsDialog(object):

    def __init__( self, snapshots, parent, path, snapshots_list, current_snapshot_id, icon_name, use_gloobus_preview ):
        self.snapshots = snapshots
        self.path = path
        self.snapshots_list = snapshots_list
        self.current_snapshot_id = current_snapshot_id
        self.icon_name = icon_name        
        self.config = snapshots.config
        self.use_gloobus_preview = use_gloobus_preview 
         
        builder = gtk.Builder()
        self.builder = builder
        self.builder.set_translation_domain('backintime')

        glade_file = os.path.join(self.config.get_app_path(), 'gnome', 'snapshotsdialog.glade')

        builder.add_from_file(glade_file)

        self.dialog = self.builder.get_object( 'SnapshotsDialog' )
        self.window = self.dialog
        self.dialog.set_transient_for( parent )

        signals = { 
            'on_list_snapshots_row_activated' : self.on_list_snapshots_row_activated,
            'on_list_snapshots_popup_menu' : self.on_list_snapshots_popup_menu,
            'on_list_snapshots_button_press_event': self.on_list_snapshots_button_press_event,
            'on_list_snapshots_drag_data_get': self.on_list_snapshots_drag_data_get,
            'on_list_snapshots_key_press_event' : self.on_list_snapshots_key_press_event,
            'on_btn_diff_with_clicked' : self.on_btn_diff_with_clicked,
            'on_btn_restore_clicked' : self.on_restore_this,
            'on_btn_delete_clicked' : self.on_btn_delete_clicked,
            'on_btn_select_all_clicked' : self.on_btn_select_all_clicked,
            'on_check_list_diff_toggled'  : self.on_check_list_diff_toggled,
            'on_check_list_equal_toggled'  : self.on_check_list_diff_toggled,
            'on_check_deep_check_toggled' : self.on_check_deep_check_toggled,
            'on_combo_equal_to_changed' : self.on_combo_equal_to_changed
        }
        
        #path
        self.edit_path = self.builder.get_object( 'edit_path' )
        
        #restore menu
        self.restore_menu = gtk.Menu()
        self.restore_menu.append(gnometools.new_menu_item(gtk.STOCK_UNDELETE, _('Restore'), self.on_restore_this))
        self.restore_menu.append(gnometools.new_menu_item(gtk.STOCK_UNDELETE, _('Restore to ...'), self.on_restore_this_to))
        self.restore_menu.show_all()
        
        self.btn_restore = self.builder.get_object('btn_restore')
        self.btn_restore.set_menu(self.restore_menu)

        #delete
        self.btn_delete = self.builder.get_object('btn_delete')

        #select all
        self.btn_select_all = self.builder.get_object('btn_select_all')

        #popup now
        #self.popup_now = gtk.Menu()
        
        #diff
        self.edit_diff_cmd = self.builder.get_object( 'edit_diff_cmd' )
        self.edit_diff_cmd_params = self.builder.get_object( 'edit_diff_cmd_params' )
        
        diff_cmd = self.config.get_str_value( 'gnome.diff.cmd', 'meld' )
        diff_cmd_params = self.config.get_str_value( 'gnome.diff.params', '%1 %2' )
        
        self.edit_diff_cmd.set_text( diff_cmd )
        self.edit_diff_cmd_params.set_text( diff_cmd_params )
        
        #setup backup folders
        self.list_snapshots = self.builder.get_object( 'list_snapshots' )
        
        # connect callbacks to widgets signals.
        builder.connect_signals(signals)
        
        text_renderer = gtk.CellRendererText()
        column = gtk.TreeViewColumn( _('Snapshots') )
        column.pack_end( text_renderer, True )
        column.add_attribute( text_renderer, 'markup', 0 )
        column.set_sort_column_id( 0 )
        self.list_snapshots.append_column( column )
        
        #display name, snapshot_id
        self.store_snapshots = gtk.ListStore( str, str )
        self.list_snapshots.set_model( self.store_snapshots )
        
        self.store_snapshots.set_sort_column_id( 0, gtk.SORT_DESCENDING )
        self.list_snapshots.get_selection().set_mode(gtk.SELECTION_MULTIPLE)
        self.list_snapshots.get_selection().connect('changed', self.on_list_snapshots_cursor_changed)
        
        #setup diff with combo
        self.combo_diff_with = self.builder.get_object( 'combo_diff_with' )
        text_renderer = gtk.CellRendererText()
        self.combo_diff_with.pack_start( text_renderer, True )
        self.combo_diff_with.add_attribute( text_renderer, 'markup', 0 )
        self.combo_diff_with.set_model( self.store_snapshots ) #use the same store

        #setup equal to combo
        self.store_snapshots_combo_equal = gtk.ListStore( str, str )
        self.store_snapshots_combo_equal.set_sort_column_id( 0, gtk.SORT_DESCENDING )
        
        self.combo_equal_to = self.builder.get_object( 'combo_equal_to' )
        text_renderer = gtk.CellRendererText()
        self.combo_equal_to.pack_start( text_renderer, True )
        self.combo_equal_to.add_attribute( text_renderer, 'markup', 0 )
        self.combo_equal_to.set_model(self.store_snapshots_combo_equal)
        
        self.update_combo_equal_to()
        self.combo_equal_to.set_sensitive(False)

        # update snapshot list
        full_path = self.snapshots.get_snapshot_path_to( self.current_snapshot_id, self.path )
        if os.path.islink( full_path ):
            self.builder.get_object( 'check_deep_check' ).hide()
        elif os.path.isdir( full_path ):
            self.builder.get_object( 'check_list_diff' ).hide()
            self.builder.get_object('check_list_equal').hide()
            self.combo_equal_to.hide()
            self.builder.get_object( 'check_deep_check' ).hide()

        self.builder.get_object( 'check_deep_check' ).set_sensitive( False )

        self.update_snapshots()

    def update_toolbar( self ):
        snapshot_ids = self.get_list_snapshot_id(True)

        if len(snapshot_ids) <= 0:
            enable_restore = False
            enable_delete = False
        elif len(snapshot_ids) == 1:
            enable_restore = len( snapshot_ids[0] ) > 1
            enable_delete = len( snapshot_ids[0] ) > 1
        else:
            enable_restore = False
            enable_delete = True
            for snapshot_id in snapshot_ids:
                if len(snapshot_id) <= 1:
                    enable_delete = False
                    
        self.btn_restore.set_sensitive(enable_restore)
        self.btn_delete.set_sensitive(enable_delete)

    def on_restore_this( self, *args ):
        snapshot_id = self.get_list_snapshot_id()
        if not snapshot_id is None:
            gnometools.restore(self, snapshot_id, self.path )

    def on_restore_this_to( self, *args ):
        snapshot_id = self.get_list_snapshot_id()
        if not snapshot_id is None:
            gnometools.restore(self, snapshot_id, self.path, True )

    def on_list_snapshots_drag_data_get( self, widget, drag_context, selection_data, info, timestamp, user_param1 = None ):
        path = self.get_list_snapshot_id(index = 2)
        if not path is None:
            path = gnomevfs.escape_path_string(path)
            selection_data.set_uris( [ 'file://' + path ] )

    def on_list_snapshots_key_press_event( self, _list, event ):
        if 32 != event.keyval:
            return False

        if not self.use_gloobus_preview:
            return False

        self.open_item( True )
        return True

    def on_list_snapshots_cursor_changed( self, _list ):
        self.update_toolbar()

    def on_list_snapshots_button_press_event( self, _list, event ):
        if event.button != 3:
            return

        if len( self.store_snapshots ) <= 0:
            return

        path = self.list_snapshots.get_path_at_pos( int( event.x ), int( event.y ) )
        if path is None:
            return
        path = path[0]
    
        self.list_snapshots.get_selection().select_path( path )
        self.update_toolbar()
        self.show_popup_menu( self.list_snapshots, event.button, event.time )

    def on_list_snapshots_popup_menu( self, _list ):
        self.show_popup_menu( _list, 1, gtk.get_current_event_time() )

    def show_popup_menu( self, _list, button, time ):
        path = self.get_list_snapshot_id()
        if path is None:
            return

        #print "popup-menu"
        popup_menu = gtk.Menu()
        popup_menu.append(gnometools.new_menu_item( gtk.image_new_from_icon_name( self.icon_name, gtk.ICON_SIZE_MENU ), _('Open'), self.on_list_snapshots_row_activated ))
        popup_menu.append( gtk.SeparatorMenuItem() )
        popup_menu.append(gnometools.new_menu_item( gtk.STOCK_JUMP_TO, _('Jump to'), self.on_list_snapshots_jumpto_item ))

        if len( path ) > 1:
            popup_menu.append( gtk.SeparatorMenuItem() )
            popup_menu.append(gnometools.new_menu_item( gtk.STOCK_UNDELETE, _('Restore'), self.on_restore_this ))
            popup_menu.append(gnometools.new_menu_item( gtk.STOCK_UNDELETE, _('Restore to ...'), self.on_restore_this_to ))

        popup_menu.append(gtk.SeparatorMenuItem())
        popup_menu.append(gnometools.new_menu_item(None, _('Diff'), self.on_list_snapshots_diff_item) )

        popup_menu.show_all()
        popup_menu.popup( None, None, None, button, time )

    def on_list_snapshots_diff_item( self, widget, data = None ):
        self.on_btn_diff_with_clicked( self.builder.get_object( 'btn_diff_with' ) )

    def on_list_snapshots_jumpto_item( self, widget, data = None ):
        self.dialog.response( gtk.RESPONSE_OK )

    def on_list_snapshots_open_item( self, widget, data = None ):
        self.open_item()

    def on_btn_diff_with_clicked( self, button ):
        if len( self.store_snapshots ) < 1:
            return

        #get path from the list
        snapshot_id = self.get_list_snapshot_id()
        if snapshot_id is None:
            return
        path1 = self.snapshots.get_snapshot_path_to( snapshot_id, self.path )

        #get path from the combo
        path2 = self.snapshots.get_snapshot_path_to( self.store_snapshots.get_value( self.combo_diff_with.get_active_iter(), 1 ), self.path )

        #check if the 2 paths are different
        if path1 == path2:
            messagebox.show_error( self.dialog, self.config, _('You can\'t compare a snapshot to itself') )
            return

        diff_cmd = self.edit_diff_cmd.get_text()
        diff_cmd_params = self.edit_diff_cmd_params.get_text()

        if not tools.check_command( diff_cmd ):
            messagebox.show_error( self.dialog, self.config, _('Command not found: %s') % diff_cmd )
            return

        params = diff_cmd_params
        params = params.replace( '%1', "\"%s\"" % path1 )
        params = params.replace( '%2', "\"%s\"" % path2 )

        cmd = diff_cmd + ' ' + params + ' &'
        os.system( cmd  )

        #check if the command changed
        old_diff_cmd = self.config.get_str_value( 'gnome.diff.cmd', 'meld' )
        old_diff_cmd_params = self.config.get_str_value( 'gnome.diff.params', '%1 %2' )
        if diff_cmd != old_diff_cmd or diff_cmd_params != old_diff_cmd_params:
            self.config.set_str_value( 'gnome.diff.cmd', diff_cmd )
            self.config.set_str_value( 'gnome.diff.params', diff_cmd_params )
            self.config.save()

    def on_btn_delete_clicked(self, *args):
        snapshot_ids = self.get_list_snapshot_id(True)
        if len(snapshot_ids) == 0:
            return
        elif len(snapshot_ids) == 1:
            msg = _('Do you really want to delete "%(file)s" in snapshot "%(snapshot_id)s?\n') \
                    % {'file' : self.path, 'snapshot_id' : snapshot_ids[0]}
        else:
            msg = _('Do you really want to delete "%(file)s" in %(count)d snapshots?\n') \
                    % {'file' : self.path, 'count' : len(snapshot_ids)}
        msg += _('WARNING: This can not be revoked!')
        if gtk.RESPONSE_YES == messagebox.show_question(self.dialog, self.config, msg):
            for snapshot_id in snapshot_ids:
                self.snapshots.delete_path(snapshot_id, self.path)

            msg = _('Exclude "%s" from future snapshots?' % self.path)
            if gtk.RESPONSE_YES == messagebox.show_question(self.dialog, self.config, msg):
                exclude = self.config.get_exclude()
                exclude.append(self.path)
                self.config.set_exclude(exclude)
            self.update_combo_equal_to()
            self.update_snapshots()

    def on_check_list_diff_toggled( self, widget, data = None ):
        deep_btn = self.builder.get_object( 'check_deep_check' )
        diff_btn = self.builder.get_object('check_list_diff')
        equal_btn = self.builder.get_object('check_list_equal')

        if widget == diff_btn:
            equal_btn.set_sensitive(not widget.get_active())
        elif widget == equal_btn:
            diff_btn.set_sensitive(not widget.get_active())

        if diff_btn.get_active() or equal_btn.get_active() and tools.check_command("md5sum"):
            deep_btn.set_sensitive(True)
        else:
            deep_btn.set_active(False)
            deep_btn.set_sensitive( False )
        self.combo_equal_to.set_sensitive(equal_btn.get_active())
        self.update_snapshots()
        
    def on_check_deep_check_toggled( self, widget, data = None ):
        self.update_snapshots()

    def on_combo_equal_to_changed(self, *args):
        self.update_snapshots()

    def update_snapshots( self):
        self.edit_path.set_text( self.path )

        #fill snapshots
        self.store_snapshots.clear()
    
        counter = 0
        index_combo_diff_with = 0
        
        # filter snapshots for uniqueness (if requested)
        list_diff  = self.builder.get_object( 'check_list_diff' ).get_active()
        deep_check = self.builder.get_object( 'check_deep_check' ).get_active()
        list_equal_to = False
        if self.builder.get_object('check_list_equal').get_active():
            iter = self.combo_equal_to.get_active_iter()
            if not iter is None:
                list_equal_to = self.snapshots.get_snapshot_path_to( self.store_snapshots_combo_equal.get_value( iter, 1 ), self.path )
        
        snapshots_filtered = self.snapshots.filter_for( self.current_snapshot_id, self.path, self.snapshots_list, list_diff, deep_check, list_equal_to )
        
        for snapshot_id in snapshots_filtered:
            self.store_snapshots.append( [ gnometools.get_snapshot_display_markup( self.snapshots, snapshot_id ), snapshot_id ] )
            if snapshot_id == self.current_snapshot_id:
                index_combo_diff_with = counter
            counter += 1

        #select first item
        if len( self.store_snapshots ) > 0:
            iter = self.store_snapshots.get_iter_first()
            if not iter is None:
                self.list_snapshots.get_selection().select_iter( iter )
            self.combo_diff_with.set_active( index_combo_diff_with )
    
            self.builder.get_object( 'btn_diff_with' ).set_sensitive( True )
            self.combo_diff_with.set_sensitive( True )
        else:
            self.builder.get_object( 'btn_diff_with' ).set_sensitive( False )
            self.combo_diff_with.set_sensitive( False )

        self.list_snapshots.grab_focus()
        self.update_toolbar()

    def update_combo_equal_to(self):
        self.store_snapshots_combo_equal.clear()
        counter = 0
        index_combo_equal_to = 0
        snapshots_filtered = self.snapshots.filter_for(self.current_snapshot_id, self.path, self.snapshots_list)
        
        for snapshot_id in snapshots_filtered:
            self.store_snapshots_combo_equal.append( [ gnometools.get_snapshot_display_markup( self.snapshots, snapshot_id ), snapshot_id ] )
            if snapshot_id == self.current_snapshot_id:
                index_combo_equal_to = counter
            counter += 1
        
        self.combo_equal_to.set_active(index_combo_equal_to)

    def on_list_snapshots_row_activated( self, _list, path, column ):
        self.open_item()

    def open_item( self, use_gloobus_preview = False ):
        snapshot_id = self.get_list_snapshot_id()
        if snapshot_id is None:
            return
        
        path = self.snapshots.get_snapshot_path_to( snapshot_id, self.path )
        if not os.path.exists( path ):
            return

        if use_gloobus_preview:
            cmd = "gloobus-preview \"%s\" &" % path
        else:
            cmd = "gnome-open \"%s\" &" % path

        os.system( cmd )

    def get_list_snapshot_id(self, multiSelection = False, index = 1):
        paths = self.list_snapshots.get_selection().get_selected_rows()[1]
        if multiSelection:
            _list = []
            for path in paths:
                iter = self.store_snapshots.get_iter(path[0])
                if not iter is None:
                    _list.append(self.store_snapshots.get_value( iter, index ))
            return _list

        iter = self.store_snapshots.get_iter(paths[0][0])
        if iter is None:
            return None
        return self.store_snapshots.get_value(iter, index)

    def on_btn_select_all_clicked(self, *args):
        '''Select all except 'Now' '''
        def iterAllItems(self):
            iter = self.get_iter_first()
            while not iter is None:
                yield iter
                iter = self.iter_next(iter)

        self.list_snapshots.get_selection().unselect_all()
        for iter in iterAllItems(self.store_snapshots):
            if len(self.store_snapshots.get_value(iter, 1)) > 1:
                self.list_snapshots.get_selection().select_iter(iter)

    def run( self ):
        snapshot_id = None
        while True:
            ret_val = self.dialog.run()
            
            if gtk.RESPONSE_OK == ret_val: #go to
                snapshot_id = self.get_list_snapshot_id()
                break
            else:
                #cancel, close ...
                break

        self.dialog.destroy()
        return snapshot_id
