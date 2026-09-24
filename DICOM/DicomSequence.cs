// Copyright (c) 2012-2017 fo-dicom contributors.
// Licensed under the Microsoft Public License (MS-PL).

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Text;

namespace Dicom
{
    public class DicomSequence : DicomItem, IEnumerable<DicomDataset>
    {
        private readonly ItemList _items;

        //the encapsulating dataset's encoding; null until the sequence is added to a dataset
        private Encoding _InheritedEncoding = null;

        public DicomSequence(DicomTag tag, params DicomDataset[] items)
            : base(tag)
        {
            if (items == null) throw new ArgumentNullException(nameof(items));
            _items = new ItemList(this);
            foreach (var item in items) _items.Add(item);
        }

        public override DicomVR ValueRepresentation
        {
            get
            {
                return DicomVR.SQ;
            }
        }

        public IList<DicomDataset> Items
        {
            get
            {
                return _items;
            }
        }

        /// <summary>
        /// Called by the encapsulating dataset when this sequence is added to it and whenever its
        /// encoding changes. Every item, present or added later, inherits this encoding unless it has
        /// its own Specific Character Set (PS3.5 7.5.3).
        /// </summary>
        internal void SetInheritedEncoding(Encoding encoding)
        {
            _InheritedEncoding = encoding;
            foreach (var item in _items)
            {
                if (item != null) item.InheritEncoding(encoding);
            }
        }

        public IEnumerator<DicomDataset> GetEnumerator()
        {
            return _items.GetEnumerator();
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
        {
            return _items.GetEnumerator();
        }

        /// <summary>
        /// Item list that applies the sequence's inherited encoding to each item as it is inserted or
        /// replaced, so items added after the sequence is attached (Items.Add, the reader) are covered.
        /// </summary>
        private sealed class ItemList : Collection<DicomDataset>
        {
            private readonly DicomSequence _owner;

            public ItemList(DicomSequence owner)
            {
                _owner = owner;
            }

            protected override void InsertItem(int index, DicomDataset item)
            {
                base.InsertItem(index, item);
                Inherit(item);
            }

            protected override void SetItem(int index, DicomDataset item)
            {
                base.SetItem(index, item);
                Inherit(item);
            }

            private void Inherit(DicomDataset item)
            {
                //a sequence not yet in a dataset has nothing to pass down; it is applied on attach
                if (item != null && _owner._InheritedEncoding != null)
                {
                    item.InheritEncoding(_owner._InheritedEncoding);
                }
            }
        }
    }
}
