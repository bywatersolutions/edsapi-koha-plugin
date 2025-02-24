<ul id="action">
    [% UNLESS ( norequests ) %]
        [% IF Koha.Preference( 'opacuserlogin' ) == 1 %]
            [% IF Koha.Preference( 'RequestOnOpac' ) == 1 %]
                [% IF ( AllowOnShelfHolds ) %]
                    <li><a class="reserve" href="/cgi-bin/koha/opac-reserve.pl?biblionumber=[% biblionumber %]">Place hold</a></li>
                [% ELSE %]
                    [% IF ( ItemsIssued ) %]
                        <li><a class="reserve" href="/cgi-bin/koha/opac-reserve.pl?biblionumber=[% biblionumber %]">Place hold</a></li>
                    [% END %]
                [% END %]
            [% END %]
        [% END %]
    [% END %]
    <li><a class="print-large" href="#" onclick="window.print();">[% EDSLANG.eds_detail_sidebar_INC_print %]</a></li>
   <!-- [%# IF Koha.Preference( 'virtualshelves' ) == 1 %]
        [%# IF ( ( Koha.Preference( 'opacuserlogin' ) == 1 ) && loggedinusername ) %]
            <li><a class="addtoshelf" href="/cgi-bin/koha/opac-addbybiblionumber.pl?biblionumber=[%# biblionumber %]" onclick="Dopop('opac-addbybiblionumber.pl?biblionumber=[% biblionumber %]'); return false;">
                Save to your lists
            </a></li>
        [%# END %]
    [%# END %] -->
    [% IF Koha.Preference( 'opacbookbag' ) == 1 %]
        [%IF RECORD.Header.DbId.match(cataloguedbid) %]
            [% IF ( incart ) %]
                <li><a data-biblionumber="[% DETAILED_RECORD.Header.An %]" class="incart cart[% DETAILED_RECORD.Header.An %]" href="#">[% EDSLANG.eds_detail_sidebar_INC_in_cart %]</a> <a class="data-biblionumber="[% DETAILED_RECORD.Header.An %]" cartRemove cartR[% DETAILED_RECORD.Header.An %]" href="#">[% EDSLANG.eds_detail_sidebar_INC_remove_cart %]</a></li>
            [% ELSE %]
                <li><a data-biblionumber="[% DETAILED_RECORD.Header.An %]" class="addtocart cart[% DETAILED_RECORD.Header.An %]" href="#">[% EDSLANG.eds_detail_sidebar_INC_add_cart %]</a>  <a style="display:none;" class="data-biblionumber="[% DETAILED_RECORD.Header.An %]" cartRemove cartR[% DETAILED_RECORD.Header.An %]" href="#">[% EDSLANG.eds_detail_sidebar_INC_remove_cart %]</a></li>
            [% END %]
        [% ELSE %]
        [% IF ( incart ) %]
                <li><a data-biblionumber="[% DETAILED_RECORD.Header.An %]|[% DETAILED_RECORD.Header.DbId %]" class="incart cart[% DETAILED_RECORD.Header.An %]|[% DETAILED_RECORD.Header.DbId %]" href="#">[% EDSLANG.eds_detail_sidebar_INC_in_cart %]</a> <a class="data-biblionumber="[% DETAILED_RECORD.Header.An %]|[% DETAILED_RECORD.Header.DbId %]" cartRemove cartR[% DETAILED_RECORD.Header.An %]|[% DETAILED_RECORD.Header.DbId %]" href="#">[% EDSLANG.eds_detail_sidebar_INC_remove_cart %]</a></li>
            [% ELSE %]
                <li><a data-biblionumber="[% DETAILED_RECORD.Header.An %]|[% DETAILED_RECORD.Header.DbId %]" class="addtocart cart[% DETAILED_RECORD.Header.An %]|[% DETAILED_RECORD.Header.DbId %]" href="#">[% EDSLANG.eds_detail_sidebar_INC_add_cart %]</a>  <a style="display:none;" class="data-biblionumber="[% DETAILED_RECORD.Header.An %]|[% DETAILED_RECORD.Header.DbId %]" cartRemove cartR[% DETAILED_RECORD.Header.An %]|[% DETAILED_RECORD.Header.DbId %]" href="#">[% EDSLANG.eds_detail_sidebar_INC_remove_cart %]</a></li>
            [% END %]
        [% END %]
    [% END %]
    [% IF ( OpacHighlightedWords && query_desc ) %]
    <li>
        <a href="#" class="highlight_toggle" id="highlight_toggle_off">Unhighlight</a>
        <a href="#" class="highlight_toggle" id="highlight_toggle_on">Highlight</a>
    </li>
    [% END %]

    [% IF ( export_options.size ) %]
        <li>
            <div id="export">
                <div class="dropdown">
                    <a id="format" class="dropdown-toggle" data-toggle="dropdown" href="#">Save record <b class="caret"></b></a>
                        <ul class="dropdown-menu pull-right" role="menu" aria-labelledby="format">
                            [% FOREACH option IN export_options %]
                                <li>
                                    <a role="menuitem" href="/cgi-bin/koha/opac-export.pl?op=export&amp;bib=[% biblionumber %]&amp;format=[% option %]">
                                        [% SWITCH option %]
                                            [% CASE 'bibtex' %]BIBTEX
                                            [% CASE 'dc' %]Dublin Core (XML)
                                            [% CASE 'endnote' %]EndNote
                                            [% CASE 'marcxml' %]MARCXML
                                            [% CASE 'marc8' %]MARC (non-Unicode/MARC-8)
                                            [% CASE 'utf8' %]MARC (Unicode/UTF-8)
                                            [% CASE 'marcstd' %]MARC (Unicode/UTF-8, Standard)
                                            [% CASE 'mods' %]MODS (XML)
                                            [% CASE 'ris' %]RIS
                                        [% END %]
                                    </a>
                                </li>
                            [% END %]
                        </ul>
                </div>
            </div>
        </li>
    [% END %]

    [% IF ( OPACSearchForTitleIn ) %]
        <li>
            <div id="moresearches_menu">
                <div class="dropdown">
                    <a id="furthersearches" class="dropdown-toggle" data-toggle="dropdown" href="#">More searches <b class="caret"></b></a>
                        <ul class="dropdown-menu pull-right" role="menu" aria-labelledby="furthersearches">
                            <li><a href="#" class="menu-inactive">Search for this title in:</a></li>
                            [% OPACSearchForTitleIn %]
                        </ul>
                </div>
            </div>
        </li>
    [% END %]
</ul>
