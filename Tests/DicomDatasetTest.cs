// Copyright (c) 2012-2017 fo-dicom contributors.
// Licensed under the Microsoft Public License (MS-PL).

namespace Dicom
{
    using System;
    using System.Collections.Generic;
    using System.Linq;

    using Xunit;

    [Collection("General")]
    public class DicomDatasetTest
    {
        #region Unit tests

        [Fact]
        public void Add_OtherDoubleElement_Succeeds()
        {
            var tag = DicomTag.DoubleFloatPixelData;
            var dataset = new DicomDataset();
            dataset.Add(tag, 3.45);
            Assert.IsType<DicomOtherDouble>(dataset.First(item => item.Tag.Equals(tag)));
        }

        [Fact]
        public void Add_OtherDoubleElementWithMultipleDoubles_Succeeds()
        {
            var tag = DicomTag.DoubleFloatPixelData;
            var dataset = new DicomDataset();
            dataset.Add(tag, 3.45, 6.78, 9.01);
            Assert.IsType<DicomOtherDouble>(dataset.First(item => item.Tag.Equals(tag)));
            Assert.Equal(3, dataset.Get<double[]>(tag).Length);
        }

        [Fact]
        public void Add_UnlimitedCharactersElement_Succeeds()
        {
            var tag = DicomTag.LongCodeValue;
            var dataset = new DicomDataset();
            dataset.Add(tag, "abc");
            Assert.IsType<DicomUnlimitedCharacters>(dataset.First(item => item.Tag.Equals(tag)));
            Assert.Equal("abc", dataset.Get<string>(tag));
        }

        [Fact]
        public void Add_UnlimitedCharactersElementWithMultipleStrings_Succeeds()
        {
            var tag = DicomTag.LongCodeValue;
            var dataset = new DicomDataset();
            dataset.Add(tag, "a", "b", "c");
            Assert.IsType<DicomUnlimitedCharacters>(dataset.First(item => item.Tag.Equals(tag)));
            Assert.Equal("c", dataset.Get<string>(tag, 2));
        }

        [Fact]
        public void Add_UniversalResourceElement_Succeeds()
        {
            var tag = DicomTag.URNCodeValue;
            var dataset = new DicomDataset();
            dataset.Add(tag, "abc");
            Assert.IsType<DicomUniversalResource>(dataset.First(item => item.Tag.Equals(tag)));
            Assert.Equal("abc", dataset.Get<string>(tag));
        }

        [Fact]
        public void Add_UniversalResourceElementWithMultipleStrings_OnlyFirstValueIsUsed()
        {
            var tag = DicomTag.URNCodeValue;
            var dataset = new DicomDataset();
            dataset.Add(tag, "a", "b", "c");
            Assert.IsType<DicomUniversalResource>(dataset.First(item => item.Tag.Equals(tag)));

            var data = dataset.Get<string[]>(tag);
            Assert.Equal(1, data.Length);
            Assert.Equal("a", data.First());
        }

        [Fact]
        public void Add_PersonName_MultipleNames_YieldsMultipleValues()
        {
            var tag = DicomTag.PerformingPhysicianName;
            var dataset = new DicomDataset();
            dataset.Add(
                tag,
                "Gustafsson^Anders^L",
                "Yates^Ian",
                "Desouky^Hesham",
                "Horn^Chris");

            var data = dataset.Get<string[]>(tag);
            Assert.Equal(4, data.Length);
            Assert.Equal("Desouky^Hesham", data[2]);
        }

        [Theory]
        [MemberData("MultiVMStringTags")]
        public void Add_MultiVMStringTags_YieldsMultipleValues(DicomTag tag, string[] values, Type expectedType)
        {
            var dataset = new DicomDataset();
            dataset.Add(tag, values);

            Assert.IsType(expectedType, dataset.First(item => item.Tag.Equals(tag)));

            var data = dataset.Get<string[]>(tag);
            Assert.Equal(values.Length, data.Length);
            Assert.Equal(values.Last(), data.Last());
        }

        [Fact]
        public void Get_IntWithoutArgumentTagNonExisting_ShouldThrow()
        {
            var dataset = new DicomDataset();
            var e = Record.Exception(() => dataset.Get<int>(DicomTag.MetersetRate));
            Assert.IsType<DicomDataException>(e);
        }

        [Fact]
        public void Get_IntWithIntArgumentTagNonExisting_ShouldThrow()
        {
            var dataset = new DicomDataset();
            var e = Record.Exception(() => dataset.Get<int>(DicomTag.MetersetRate, 20));
            Assert.IsType<DicomDataException>(e);
        }

        [Fact]
        public void Get_NonGenericWithIntArgumentTagNonExisting_ShouldNotThrow()
        {
            var dataset = new DicomDataset();
            var e = Record.Exception(() => Assert.Equal(20, dataset.Get(DicomTag.MetersetRate, 20)));
            Assert.Null(e);
        }

        [Fact]
        public void Get_IntOutsideRange_ShouldThrow()
        {
            var tag = DicomTag.SelectorISValue;
            var dataset = new DicomDataset();
            dataset.Add(tag, 3, 4, 5);

            var e = Record.Exception(() => dataset.Get<int>(tag, 10));
            Assert.IsType<DicomDataException>(e);
        }

        [Fact]
        public void Get_NonGenericIntArgumentEmptyElement_ShouldNotThrow()
        {
            var tag = DicomTag.SelectorISValue;
            var dataset = new DicomDataset();
            dataset.Add(tag, new int[0]);

            var e = Record.Exception(() => Assert.Equal(10, dataset.Get(tag, 10)));
            Assert.Null(e);
        }

        [Fact]
        public void Get_NullableReturnType_ReturnsDefinedValue()
        {
            var tag = DicomTag.SelectorULValue;
            const uint expected = 100u;
            var dataset = new DicomDataset { { tag, expected } };

            var actual = dataset.Get<uint?>(tag).Value;
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void DicomSignedShortTest()
        {
            short[] values = new short[] { 5 }; //single Value element
            DicomSignedShort element = new DicomSignedShort(DicomTag.TagAngleSecondAxis, values);

            TestAddElementToDatasetAsString<short>(element, values);

            values = new short[] { 5, 8 }; //multi-value element
            element = new DicomSignedShort(DicomTag.CenterOfCircularExposureControlSensingRegion, values);

            TestAddElementToDatasetAsString<short>(element, values);
        }

        [Fact]
        public void DicomAttributeTagTest()
        {
            var expected = new DicomTag[] { DicomTag.ALinePixelSpacing }; //single value
            DicomElement element = new DicomAttributeTag(DicomTag.DimensionIndexPointer, expected);


            TestAddElementToDatasetAsString<string>(element, expected.Select(n => n.ToString("J", null)).ToArray());

            expected = new DicomTag[] { DicomTag.ALinePixelSpacing, DicomTag.AccessionNumber }; //multi-value
            element = new DicomAttributeTag(DicomTag.FrameIncrementPointer, expected);

            TestAddElementToDatasetAsString(element, expected.Select(n => n.ToString("J", null)).ToArray());
        }

        [Fact]
        public void DicomUnsignedShortTest()
        {
            ushort[] testValues = new ushort[] { 1, 2, 3, 4, 5 };

            var element = new DicomUnsignedShort(DicomTag.ReferencedFrameNumbersRETIRED, testValues);

            TestAddElementToDatasetAsString<ushort>(element, testValues);
        }

        [Fact]
        public void DicomSignedLongTest()
        {
            var testValues = new int[] { 0, 1, 2 };
            var element = new DicomSignedLong(DicomTag.ReferencePixelX0, testValues);

            TestAddElementToDatasetAsString(element, testValues);
        }

        [Fact]
        public void DicomOtherDoubleTest()
        {
            var testValues = new double[] { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80 };

            var element = new DicomOtherDouble(DicomTag.DoubleFloatPixelData, testValues);

            TestAddElementToDatasetAsByteBuffer<double>(element, testValues);
        }

        [Fact]
        public void DicomOtherByteTest()
        {
            var testValues = new byte[] { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80 };

            var element = new DicomOtherByte(DicomTag.PixelData, testValues);

            TestAddElementToDatasetAsByteBuffer(element, testValues);
        }

        [Fact]
        public void Constructor_FromDataset_DataReproduced()
        {
            var ds = new DicomDataset { { DicomTag.PatientID, "1" } };
            var sps1 = new DicomDataset { { DicomTag.ScheduledStationName, "1" } };
            var sps2 = new DicomDataset { { DicomTag.ScheduledStationName, "2" } };
            var spcs1 = new DicomDataset { { DicomTag.ContextIdentifier, "1" } };
            var spcs2 = new DicomDataset { { DicomTag.ContextIdentifier, "2" } };
            var spcs3 = new DicomDataset { { DicomTag.ContextIdentifier, "3" } };
            sps1.Add(new DicomSequence(DicomTag.ScheduledProtocolCodeSequence, spcs1, spcs2));
            sps2.Add(new DicomSequence(DicomTag.ScheduledProtocolCodeSequence, spcs3));
            ds.Add(new DicomSequence(DicomTag.ScheduledProcedureStepSequence, sps1, sps2));

            Assert.Equal("1", ds.Get<string>(DicomTag.PatientID));
            Assert.Equal(
                "1",
                ds.Get<DicomSequence>(DicomTag.ScheduledProcedureStepSequence).Items[0].Get<string>(
                    DicomTag.ScheduledStationName));
            Assert.Equal(
                "2",
                ds.Get<DicomSequence>(DicomTag.ScheduledProcedureStepSequence).Items[1].Get<string>(
                    DicomTag.ScheduledStationName));
            Assert.Equal(
                "1",
                ds.Get<DicomSequence>(DicomTag.ScheduledProcedureStepSequence).Items[0].Get<DicomSequence>(
                    DicomTag.ScheduledProtocolCodeSequence).Items[0].Get<string>(DicomTag.ContextIdentifier));
            Assert.Equal(
                "2",
                ds.Get<DicomSequence>(DicomTag.ScheduledProcedureStepSequence).Items[0].Get<DicomSequence>(
                    DicomTag.ScheduledProtocolCodeSequence).Items[1].Get<string>(DicomTag.ContextIdentifier));
            Assert.Equal(
                "3",
                ds.Get<DicomSequence>(DicomTag.ScheduledProcedureStepSequence).Items[1].Get<DicomSequence>(
                    DicomTag.ScheduledProtocolCodeSequence).Items[0].Get<string>(DicomTag.ContextIdentifier));
        }

        [Fact]
        public void Constructor_FromDataset_SequenceItemsNotLinked()
        {
            var ds = new DicomDataset { { DicomTag.PatientID, "1" } };
            var sps = new DicomDataset { { DicomTag.ScheduledStationName, "1" } };
            var spcs = new DicomDataset { { DicomTag.ContextIdentifier, "1" } };
            sps.Add(new DicomSequence(DicomTag.ScheduledProtocolCodeSequence, spcs));
            ds.Add(new DicomSequence(DicomTag.ScheduledProcedureStepSequence, sps));

            var ds2 = new DicomDataset(ds);
            ds2.AddOrUpdate(DicomTag.PatientID, "2");
            ds2.Get<DicomSequence>(DicomTag.ScheduledProcedureStepSequence).Items[0].AddOrUpdate(DicomTag.ScheduledStationName, "2");
            ds2.Get<DicomSequence>(DicomTag.ScheduledProcedureStepSequence).Items[0].Get<DicomSequence>(
                DicomTag.ScheduledProtocolCodeSequence).Items[0].AddOrUpdate(DicomTag.ContextIdentifier, "2");

            Assert.Equal("1", ds.Get<string>(DicomTag.PatientID));
            Assert.Equal(
                "1",
                ds.Get<DicomSequence>(DicomTag.ScheduledProcedureStepSequence).Items[0].Get<string>(
                    DicomTag.ScheduledStationName));
            Assert.Equal(
                "1",
                ds.Get<DicomSequence>(DicomTag.ScheduledProcedureStepSequence).Items[0].Get<DicomSequence>(
                    DicomTag.ScheduledProtocolCodeSequence).Items[0].Get<string>(DicomTag.ContextIdentifier));
        }

        [Fact]
        public void InternalTransferSyntax_Setter_AppliesToAllSequenceDepths()
        {
            var ds = new DicomDataset { { DicomTag.PatientID, "1" } };
            var sps = new DicomDataset { { DicomTag.ScheduledStationName, "1" } };
            var spcs = new DicomDataset { { DicomTag.ContextIdentifier, "1" } };
            sps.Add(new DicomSequence(DicomTag.ScheduledProtocolCodeSequence, spcs));
            ds.Add(new DicomSequence(DicomTag.ScheduledProcedureStepSequence, sps));

            var newSyntax = DicomTransferSyntax.DeflatedExplicitVRLittleEndian;
            ds.InternalTransferSyntax = newSyntax;
            Assert.Equal(newSyntax, ds.InternalTransferSyntax);
            Assert.Equal(
                newSyntax,
                ds.Get<DicomSequence>(DicomTag.ScheduledProcedureStepSequence).Items[0].InternalTransferSyntax);
            Assert.Equal(
                newSyntax,
                ds.Get<DicomSequence>(DicomTag.ScheduledProcedureStepSequence).Items[0].Get<DicomSequence>(
                    DicomTag.ScheduledProtocolCodeSequence).Items[0].InternalTransferSyntax);
        }

        [Fact]
        public void Get_ArrayWhenTagExistsEmpty_ShouldReturnEmptyArray()
        {
            var tag = DicomTag.GridFrameOffsetVector;
            var ds = new DicomDataset();
            ds.Add(tag, (string[])null);

            var array = ds.Get<string[]>(tag);
            Assert.Equal(0, array.Length);
        }

        #endregion

        #region Character set encoding

        // Text that no single-byte fallback can carry: Latin-1, Cyrillic, CJK. \u escapes keep the
        // source file's own encoding out of it.
        private const string Cyrillic = "Рентген";
        private const string Latin = "Zoë";
        private const string Mixed = "TEST^Zoë Рентген 犬";

        private static readonly System.Text.Encoding Utf8 = DicomEncoding.GetEncoding("ISO_IR 192");
        private static readonly System.Text.Encoding Latin1 = DicomEncoding.GetEncoding("ISO_IR 100");

        [Fact]
        public void SpecificCharacterSet_AddedAfterText_ReencodesLosslessly()
        {
            var ds = new DicomDataset();
            ds.AddOrUpdate(DicomTag.StudyDescription, Cyrillic);
            // until the character set is declared the bytes are ASCII, and reads reflect the bytes
            Assert.Equal("???????", ds.Get<string>(DicomTag.StudyDescription));

            ds.AddOrUpdate(DicomTag.SpecificCharacterSet, "ISO_IR 192");

            AssertText(ds, DicomTag.StudyDescription, Cyrillic, Utf8);
        }

        [Fact]
        public void SpecificCharacterSet_AddedAfterText_PersonNameAndMultiValueKeepValues()
        {
            var ds = new DicomDataset();
            ds.AddOrUpdate(DicomTag.PatientName, Mixed);
            ds.AddOrUpdate(DicomTag.OtherPatientIDs, Latin + "\\" + Cyrillic);

            ds.AddOrUpdate(DicomTag.SpecificCharacterSet, "ISO_IR 192");

            AssertText(ds, DicomTag.PatientName, Mixed, Utf8);
            Assert.Equal(new[] { Latin, Cyrillic }, ds.Get<string[]>(DicomTag.OtherPatientIDs));
        }

        [Fact]
        public void SpecificCharacterSet_ChangedTwice_StillLossless()
        {
            // Latin-1 cannot hold Cyrillic, so only the kept source text makes the second step lossless
            var ds = new DicomDataset();
            ds.AddOrUpdate(DicomTag.StudyDescription, Cyrillic);
            ds.AddOrUpdate(DicomTag.SpecificCharacterSet, "ISO_IR 100");
            ds.AddOrUpdate(DicomTag.SpecificCharacterSet, "ISO_IR 192");

            AssertText(ds, DicomTag.StudyDescription, Cyrillic, Utf8);
        }

        [Fact]
        public void SpecificCharacterSet_Changed_ElementBuiltFromBytesIsDecodedAndReencoded()
        {
            var ds = new DicomDataset();
            ds.AddOrUpdate(DicomTag.SpecificCharacterSet, "ISO_IR 100");
            ds.AddOrUpdate(new DicomLongString(DicomTag.StudyDescription, Latin1,
                new IO.Buffer.MemoryByteBuffer(Latin1.GetBytes(Latin + " "))));

            ds.AddOrUpdate(DicomTag.SpecificCharacterSet, "ISO_IR 192");

            AssertText(ds, DicomTag.StudyDescription, Latin, Utf8);
        }

        [Fact]
        public void SpecificCharacterSet_Changed_NonTextValuesUnchanged()
        {
            var ds = new DicomDataset();
            ds.AddOrUpdate(DicomTag.StudyDate, "20260923");
            ds.AddOrUpdate(DicomTag.StudyInstanceUID, "1.2.3.4");
            ds.AddOrUpdate(DicomTag.Modality, "CR");

            ds.AddOrUpdate(DicomTag.SpecificCharacterSet, "ISO_IR 192");

            Assert.Equal("20260923", ds.Get<string>(DicomTag.StudyDate));
            Assert.Equal("1.2.3.4", ds.Get<string>(DicomTag.StudyInstanceUID));
            Assert.Equal("CR", ds.Get<string>(DicomTag.Modality));
        }

        [Fact]
        public void SequenceItem_BuiltThenAttached_InheritsParentEncoding()
        {
            // the MWL Scheduled Procedure Step pattern: the item is filled before it is attached
            var ds = new DicomDataset();
            ds.AddOrUpdate(DicomTag.SpecificCharacterSet, "ISO_IR 192");
            var item = new DicomDataset();
            item.AddOrUpdate(DicomTag.ScheduledProcedureStepDescription, Cyrillic);

            ds.AddOrUpdate(DicomTag.ScheduledProcedureStepSequence, item);

            AssertText(FirstItem(ds, DicomTag.ScheduledProcedureStepSequence),
                DicomTag.ScheduledProcedureStepDescription, Cyrillic, Utf8);
        }

        [Fact]
        public void SequenceItem_AddedAfterSequenceAttached_InheritsParentEncoding()
        {
            var ds = new DicomDataset();
            ds.AddOrUpdate(DicomTag.SpecificCharacterSet, "ISO_IR 192");
            ds.AddOrUpdate(new DicomSequence(DicomTag.ScheduledProcedureStepSequence));
            var item = new DicomDataset();
            item.AddOrUpdate(DicomTag.ScheduledProcedureStepDescription, Cyrillic);

            ds.Get<DicomSequence>(DicomTag.ScheduledProcedureStepSequence).Items.Add(item);
            item.AddOrUpdate(DicomTag.ScheduledStationName, Latin);

            AssertText(item, DicomTag.ScheduledProcedureStepDescription, Cyrillic, Utf8);
            AssertText(item, DicomTag.ScheduledStationName, Latin, Utf8);
        }

        [Fact]
        public void SequenceItem_ParentCharacterSetSetAfterAttach_Reencoded()
        {
            var ds = new DicomDataset();
            var item = new DicomDataset();
            item.AddOrUpdate(DicomTag.ScheduledProcedureStepDescription, Cyrillic);
            ds.AddOrUpdate(DicomTag.ScheduledProcedureStepSequence, item);

            ds.AddOrUpdate(DicomTag.SpecificCharacterSet, "ISO_IR 192");

            AssertText(FirstItem(ds, DicomTag.ScheduledProcedureStepSequence),
                DicomTag.ScheduledProcedureStepDescription, Cyrillic, Utf8);
        }

        [Fact]
        public void SequenceItem_WithOwnCharacterSet_KeepsItAndChildrenInheritFromIt()
        {
            // PS3.5 7.5.3: an item's own Specific Character Set applies to it and its children
            var ds = new DicomDataset();
            ds.AddOrUpdate(DicomTag.SpecificCharacterSet, "ISO_IR 192");
            var item = new DicomDataset();
            item.AddOrUpdate(DicomTag.SpecificCharacterSet, "ISO_IR 100");
            item.AddOrUpdate(DicomTag.ScheduledProcedureStepDescription, Latin);
            var child = new DicomDataset();
            child.AddOrUpdate(DicomTag.CodeMeaning, Latin);
            item.AddOrUpdate(DicomTag.ScheduledProtocolCodeSequence, child);

            ds.AddOrUpdate(DicomTag.ScheduledProcedureStepSequence, item);

            AssertText(item, DicomTag.ScheduledProcedureStepDescription, Latin, Latin1);
            AssertText(child, DicomTag.CodeMeaning, Latin, Latin1);

            // and changing the parent's character set does not override the item's
            ds.AddOrUpdate(DicomTag.SpecificCharacterSet, "ISO_IR 100");
            ds.AddOrUpdate(DicomTag.SpecificCharacterSet, "ISO_IR 192");
            AssertText(item, DicomTag.ScheduledProcedureStepDescription, Latin, Latin1);
        }

        [Fact]
        public void Clone_SequenceItems_KeepEncodingAndOriginalUnaffected()
        {
            var ds = new DicomDataset();
            ds.AddOrUpdate(DicomTag.SpecificCharacterSet, "ISO_IR 192");
            var item = new DicomDataset();
            item.AddOrUpdate(DicomTag.ScheduledProcedureStepDescription, Cyrillic);
            ds.AddOrUpdate(DicomTag.ScheduledProcedureStepSequence, item);

            var clone = ds.Clone();
            AssertText(FirstItem(clone, DicomTag.ScheduledProcedureStepSequence),
                DicomTag.ScheduledProcedureStepDescription, Cyrillic, Utf8);

            clone.AddOrUpdate(DicomTag.SpecificCharacterSet, "ISO_IR 100");
            AssertText(FirstItem(ds, DicomTag.ScheduledProcedureStepSequence),
                DicomTag.ScheduledProcedureStepDescription, Cyrillic, Utf8);
        }

        [Fact]
        public void Sequence_NotInADataset_LeavesItemsAlone()
        {
            var item = new DicomDataset();
            item.AddOrUpdate(DicomTag.ScheduledProcedureStepDescription, Cyrillic);

            var sequence = new DicomSequence(DicomTag.ScheduledProcedureStepSequence, item);

            Assert.Single(sequence.Items);
            Assert.Equal("???????", item.Get<string>(DicomTag.ScheduledProcedureStepDescription));
        }

        [Fact]
        public void ReadBack_StringAddedToReceivedSequenceItem_UsesInheritedEncoding()
        {
            // reader-created items used to default to ASCII for anything added to them later
            var ds = new DicomDataset();
            ds.AddOrUpdate(DicomTag.SOPClassUID, DicomUID.SecondaryCaptureImageStorage);
            ds.AddOrUpdate(DicomTag.SOPInstanceUID, DicomUID.Generate());
            ds.AddOrUpdate(DicomTag.SpecificCharacterSet, "ISO_IR 192");
            var item = new DicomDataset();
            item.AddOrUpdate(DicomTag.ScheduledProcedureStepDescription, Cyrillic);
            ds.AddOrUpdate(DicomTag.ScheduledProcedureStepSequence, item);

            var stream = new System.IO.MemoryStream();
            new DicomFile(ds).Save(stream);
            stream.Position = 0;
            var received = FirstItem(DicomFile.Open(stream).Dataset, DicomTag.ScheduledProcedureStepSequence);
            received.AddOrUpdate(DicomTag.ScheduledStationName, Latin);

            AssertText(received, DicomTag.ScheduledProcedureStepDescription, Cyrillic, Utf8);
            AssertText(received, DicomTag.ScheduledStationName, Latin, Utf8);
        }

        [Fact]
        public void UniversalResource_AlwaysDefaultRepertoire()
        {
            // PS3.5 6.1.2.2: UR is not affected by Specific Character Set
            const string url = "https://example.com/wado?studyUID=1.2.3";
            var ds = new DicomDataset();
            ds.AddOrUpdate(DicomTag.SpecificCharacterSet, "ISO_IR 192");
            ds.AddOrUpdate(DicomTag.RetrieveURL, url);

            Assert.Equal(DicomEncoding.Default, ds.Get<DicomUniversalResource>(DicomTag.RetrieveURL).Encoding);
            Assert.Equal(url, ds.Get<string>(DicomTag.RetrieveURL));

            ds.AddOrUpdate(DicomTag.SOPClassUID, DicomUID.SecondaryCaptureImageStorage);
            ds.AddOrUpdate(DicomTag.SOPInstanceUID, DicomUID.Generate());
            var stream = new System.IO.MemoryStream();
            new DicomFile(ds).Save(stream);
            stream.Position = 0;
            var read = DicomFile.Open(stream).Dataset;
            Assert.Equal(DicomEncoding.Default, read.Get<DicomUniversalResource>(DicomTag.RetrieveURL).Encoding);
            Assert.Equal(url, read.Get<string>(DicomTag.RetrieveURL));
        }

        #endregion

        #region Support methods

        /// <summary>
        /// Asserts both the decoded value and the stored bytes (DICOM padding stripped), since a
        /// correct-looking label over wrongly encoded bytes is exactly the failure being guarded.
        /// </summary>
        private static void AssertText(DicomDataset ds, DicomTag tag, string expected, System.Text.Encoding encoding)
        {
            Assert.Equal(expected, ds.Get<string>(tag));
            byte[] raw = ds.Get<byte[]>(tag);
            int length = raw.Length;
            while (length > 0 && (raw[length - 1] == 0x20 || raw[length - 1] == 0x00)) length--;
            Assert.Equal(BitConverter.ToString(encoding.GetBytes(expected)), BitConverter.ToString(raw, 0, length));
        }

        private static DicomDataset FirstItem(DicomDataset ds, DicomTag sequenceTag)
        {
            return ds.Get<DicomSequence>(sequenceTag).Items[0];
        }

        private void TestAddElementToDatasetAsString<T>(DicomElement element, T[] testValues)
        {
            DicomDataset ds = new DicomDataset();
            string[] stringValues;


            if (typeof(T) == typeof(string))
            {
                stringValues = testValues.Cast<string>().ToArray();
            }
            else
            {
                stringValues = testValues.Select(x => x.ToString()).ToArray();
            }


            ds.AddOrUpdate(element.Tag, stringValues);


            for (int index = 0; index < element.Count; index++)
            {
                string val;

                val = GetStringValue(element, ds, index);

                Assert.Equal(stringValues[index], val);
            }

            if (element.Tag.DictionaryEntry.ValueMultiplicity.Maximum > 1)
            {
                var stringValue = string.Join("\\", testValues);

                ds.AddOrUpdate(element.Tag, stringValue);

                for (int index = 0; index < element.Count; index++)
                {
                    string val;

                    val = GetStringValue(element, ds, index);

                    Assert.Equal(stringValues[index], val);
                }
            }
        }

        private string GetStringValue(DicomElement element, DicomDataset ds, int index)
        {
            string val;


            if (element.ValueRepresentation == DicomVR.AT)
            {
                //Should this be a updated in the AT DicomTag?
                val = GetATElementValue(element, ds, index);
            }
            else
            {
                val = ds.Get<string>(element.Tag, index);
            }

            return val;
        }

        private static string GetATElementValue(DicomElement element, DicomDataset ds, int index)
        {
            var atElement = ds.Get<DicomElement>(element.Tag, null);

            var testValue = atElement.Get<DicomTag>(index);

            return testValue.ToString("J", null);
        }

        private void TestAddElementToDatasetAsByteBuffer<T>(DicomElement element, T[] testValues)
        {
            DicomDataset ds = new DicomDataset();


            ds.Add(element.Tag, element.Buffer);

            for (int index = 0; index < testValues.Count(); index++)
            {
                Assert.Equal(testValues[index], ds.Get<T>(element.Tag, index));
            }
        }

        #endregion

        #region Support data

        public static IEnumerable<object[]> MultiVMStringTags
        {
            get
            {
                yield return
                    new object[]
                        {
                            DicomTag.ReferencedFrameNumber, new[] { "3", "5", "8" },
                            typeof(DicomIntegerString)
                        };
                yield return
                    new object[]
                        {
                            DicomTag.EventElapsedTimes, new[] { "3.2", "5.8", "8.7" },
                            typeof(DicomDecimalString)
                        };
                yield return
                new object[]
                        {
                            DicomTag.PatientTelephoneNumbers, new[] { "0271-22117", "070-669 5073", "0270-11204" },
                            typeof(DicomShortString)
                        };
                yield return
                new object[]
                        {
                            DicomTag.EventTimerNames, new[] { "a", "b", "c", "e", "f" },
                            typeof(DicomLongString)
                        };
                yield return
                new object[]
                        {
                            DicomTag.ConsultingPhysicianName, new[] { "a", "b", "c", "e", "f" },
                            typeof(DicomPersonName)
                        };
                yield return
                new object[]
                        {
                            DicomTag.SOPClassesSupported, new[] { "1.2.3", "4.5.6", "7.8.8.9" },
                            typeof(DicomUniqueIdentifier)
                        };
            }
        }

        #endregion
    }
}
